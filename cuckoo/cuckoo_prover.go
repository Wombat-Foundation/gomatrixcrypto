package cuckoo

import (
	"fmt"
	"slices"
	"time"
)

// bitset is a compact, fixed-size set of bits used in place of map[X]bool
// for the O(2^EdgeBits) and O(maxNonce) tracking arrays in FindProof. At
// production-scale parameters (EdgeBits=29) those sets have hundreds of
// millions of members; a Go map's per-entry bucket overhead would put total
// memory use in the tens of gigabytes where a bitset needs tens of
// megabytes.
type bitset []uint64

type labeledEdge struct {
	nonce uint32
	u, v  uint64
}

func newBitset(n uint64) bitset {
	return make(bitset, (n+63)/64)
}

func (b bitset) get(i uint64) bool {
	return b[i>>6]&(1<<(i&63)) != 0
}

func (b bitset) set(i uint64) {
	b[i>>6] |= 1 << (i & 63)
}

func (b bitset) clear(i uint64) {
	b[i>>6] &^= 1 << (i & 63)
}

// bumpLeafCounter advances a saturating 0/1/2+ counter for node, encoded as
// one bit each in lo and hi (hi set means "2 or more, no longer a leaf
// candidate").
func bumpLeafCounter(lo, hi bitset, node uint64) {
	if hi.get(node) {
		return
	}
	if lo.get(node) {
		hi.set(node)
		return
	}
	lo.set(node)
}

func isLeafCounter(lo, hi bitset, node uint64) bool {
	return lo.get(node) && !hi.get(node)
}

var dfsLogInterval = 200000

// FindProof performs a bounded search for a valid cycle.
//
// It uses the usual Cuckoo Cycle first step: trim edges attached to leaf
// nodes before doing any path search. This is still a compact CPU helper,
// not a competitive production miner.
//
// Leaf trimming is done in bulk rounds using only two O(2^EdgeBits)-bit
// bitmaps (a saturating per-node counter) to find edges safe to drop,
// recomputing each edge's endpoints from its nonce via SipHash instead of
// storing them. This is the same "lean" trimming trick production Cuckoo
// Cycle miners use: it trades extra SipHash recomputation for keeping
// memory at a small fraction of the graph size — a full O(edges) adjacency
// list at production-scale parameters (e.g. EdgeBits=29) would otherwise
// require tens of gigabytes. Once trimming has shrunk the live edge set to
// a small survivor set, an exact incremental peel plus DFS run over just
// those survivors, which is cheap to do with ordinary maps.
//
// The bulk rounds stop as soon as returns diminish rather than chasing full
// convergence, since the incremental peel that follows finishes the exact
// cleanup cheaply on whatever remains — pushing bulk rounds all the way to
// a fixed point can add a long tail of low-yield, still O(maxNonce)-cost
// rounds for no benefit.
//
// An optional onProgress callback, if provided, is called with a line of
// human-readable status for each trimming round and DFS milestone — useful
// for confirming a large production-scale search is still making progress.
func FindProof(cfg Config, seed []byte, maxNonce uint32, onProgress ...func(string)) ([]uint32, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	words, err := seedWords(seed)
	if err != nil {
		return nil, err
	}

	var progress func(string)
	if len(onProgress) > 0 {
		progress = onProgress[0]
	}
	logf := func(format string, args ...any) {
		if progress != nil {
			progress(fmt.Sprintf(format, args...))
		}
	}

	startTime := time.Now()
	numEdges := uint64(maxNonce)
	// Each partition now spans the full 2^EdgeBits node range (nodeMask is
	// full-width), and u/v encode the partition as an extra low bit, so the
	// combined tagged node-id space is 2^(EdgeBits+1).
	nodeCount := uint64(2) << cfg.EdgeBits
	mask := cfg.nodeMask()

	edgeEndpoints := func(nonce uint32) (u, v uint64) {
		u = (siphash24(words, uint64(nonce)<<1) & mask) << 1
		v = ((siphash24(words, (uint64(nonce)<<1)|1) & mask) << 1) | 1
		return
	}

	logf("cuckoo: trimming graph EdgeBits=%d edges=%d nodes=%d", cfg.EdgeBits, numEdges, nodeCount)

	alive := newBitset(numEdges)
	for i := range alive {
		alive[i] = ^uint64(0)
	}

	lo := newBitset(nodeCount)
	hi := newBitset(nodeCount)
	aliveCount := numEdges
	// Once the live set is this small, the map-based incremental peel below
	// finishes cheaply, so further bulk rounds aren't worth their O(maxNonce)
	// scan cost.
	survivorTarget := uint64(1) << 22
	const maxTrimRounds = 64
	for round := 0; round < maxTrimRounds && aliveCount > survivorTarget; round++ {
		removedThisRound := trimAliveEdges(alive, lo, hi, maxNonce, edgeEndpoints)
		aliveCount -= removedThisRound
		logf("cuckoo: trim round %d: -%d edges, %d alive (elapsed %s)", round+1, removedThisRound, aliveCount, time.Since(startTime).Round(time.Millisecond))
		// Diminishing returns: once a round clears under 0.1% of what's
		// left, further rounds aren't worth their fixed O(maxNonce) scan
		// cost — hand the remainder to the incremental peel instead.
		if removedThisRound == 0 || removedThisRound*1000 < aliveCount {
			break
		}
	}
	survivors := collectSurvivors(alive, maxNonce, aliveCount, edgeEndpoints)
	logf("cuckoo: bulk trimming done: %d survivor edges (elapsed %s)", len(survivors), time.Since(startTime).Round(time.Millisecond))

	// The bulk rounds above only approximate the 2-core: each round removes
	// leaves visible in that round's snapshot, so a chain of leaves can take
	// several rounds to fully unwind. Finish the exact peel now with a
	// cheap incremental pass — the survivor set is small enough that map
	// overhead no longer matters.
	degrees := map[uint64]int{}
	incident := map[uint64][]int{}
	for idx, e := range survivors {
		degrees[e.u]++
		degrees[e.v]++
		incident[e.u] = append(incident[e.u], idx)
		incident[e.v] = append(incident[e.v], idx)
	}

	removed := make([]bool, len(survivors))
	queue := make([]uint64, 0, len(degrees))
	for node, degree := range degrees {
		if degree == 1 {
			queue = append(queue, node)
		}
	}

	for head := 0; head < len(queue); head++ {
		node := queue[head]
		if degrees[node] != 1 {
			continue
		}

		edgeIdx := -1
		for _, idx := range incident[node] {
			if !removed[idx] {
				edgeIdx = idx
				break
			}
		}
		removed[edgeIdx] = true
		edge := survivors[edgeIdx]
		for _, endpoint := range [...]uint64{edge.u, edge.v} {
			degrees[endpoint]--
			if degrees[endpoint] == 1 {
				queue = append(queue, endpoint)
			}
		}
	}

	survivingEdges := 0
	for _, r := range removed {
		if !r {
			survivingEdges++
		}
	}
	logf("cuckoo: exact peel done: %d edges in 2-core (elapsed %s)", survivingEdges, time.Since(startTime).Round(time.Millisecond))

	path := make([]uint32, 0, cfg.ProofSize)
	usedEdges := make([]bool, len(survivors))
	seenNodes := map[uint64]bool{}
	var dfs func(startNode, currentNode uint64, depth int) ([]uint32, bool)

	dfs = func(startNode, currentNode uint64, depth int) ([]uint32, bool) {
		if depth == cfg.ProofSize {
			if currentNode == startNode {
				proof := append([]uint32(nil), path...)
				slices.Sort(proof)
				if Verify(cfg, seed, proof) == nil {
					return proof, true
				}
			}
			return nil, false
		}

		for _, nextIdx := range incident[currentNode] {
			if removed[nextIdx] || usedEdges[nextIdx] {
				continue
			}
			next := survivors[nextIdx]
			nextNode := next.u
			if nextNode == currentNode {
				nextNode = next.v
			}
			if nextNode != startNode && seenNodes[nextNode] {
				continue
			}
			usedEdges[nextIdx] = true
			seenNodes[nextNode] = true
			path = append(path, next.nonce)
			if proof, ok := dfs(startNode, nextNode, depth+1); ok {
				return proof, true
			}
			path = path[:len(path)-1]
			delete(seenNodes, nextNode)
			usedEdges[nextIdx] = false
		}
		return nil, false
	}

	// dfsLogInterval (200k+ failed starting-edge attempts) is only reached
	// at production-scale graph sizes (EdgeBits~23+), where a single
	// FindProof call already costs 20-30+ seconds. Covering it would add
	// that cost to every test run, so it's left undocumented-but-uncovered
	// alongside the bulk-trim loop's rarer paths.
	for startIdx, start := range survivors {
		if removed[startIdx] {
			continue
		}
		logDFSProgress(startIdx, len(survivors), startTime, logf)
		usedEdges[startIdx] = true
		seenNodes[start.u] = true
		seenNodes[start.v] = true
		path = append(path[:0], start.nonce)
		if proof, ok := dfs(start.u, start.v, 1); ok {
			logf("cuckoo: found proof after %d starting edges tried (elapsed %s)", startIdx+1, time.Since(startTime).Round(time.Millisecond))
			return proof, nil
		}
		usedEdges[startIdx] = false
		delete(seenNodes, start.u)
		delete(seenNodes, start.v)
	}

	logf("cuckoo: no cycle found among %d survivor edges (elapsed %s)", len(survivors), time.Since(startTime).Round(time.Millisecond))
	return nil, ErrNoSolution
}

func trimAliveEdges(alive bitset, lo, hi bitset, maxNonce uint32, edgeEndpoints func(uint32) (uint64, uint64)) uint64 {
	for i := range lo {
		lo[i] = 0
		hi[i] = 0
	}
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		if !alive.get(uint64(nonce)) {
			continue
		}
		u, v := edgeEndpoints(nonce)
		bumpLeafCounter(lo, hi, u)
		bumpLeafCounter(lo, hi, v)
	}

	removedThisRound := uint64(0)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		if !alive.get(uint64(nonce)) {
			continue
		}
		u, v := edgeEndpoints(nonce)
		if isLeafCounter(lo, hi, u) || isLeafCounter(lo, hi, v) {
			alive.clear(uint64(nonce))
			removedThisRound++
		}
	}
	return removedThisRound
}

func collectSurvivors(alive bitset, maxNonce uint32, aliveCount uint64, edgeEndpoints func(uint32) (uint64, uint64)) []labeledEdge {
	survivors := make([]labeledEdge, 0, aliveCount)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		if !alive.get(uint64(nonce)) {
			continue
		}
		u, v := edgeEndpoints(nonce)
		survivors = append(survivors, labeledEdge{nonce: nonce, u: u, v: v})
	}
	return survivors
}

func logDFSProgress(startIdx, total int, startTime time.Time, logf func(string, ...any)) {
	if startIdx > 0 && startIdx%dfsLogInterval == 0 {
		logf("cuckoo: dfs: tried %d/%d starting edges (elapsed %s)", startIdx, total, time.Since(startTime).Round(time.Millisecond))
	}
}
