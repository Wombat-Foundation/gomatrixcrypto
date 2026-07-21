// Package cuckoo implements Cuckoo Cycle proof derivation and verification.
package cuckoo

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"time"
)

const ProofSize = 42

var (
	ErrInvalidEdgeBits = errors.New("edge bits out of range")
	ErrInvalidSeed     = errors.New("invalid graph seed")
	ErrInvalidProof    = errors.New("invalid cuckoo cycle proof")
	ErrNoSolution      = errors.New("no cycle found")
)

// Config defines the cycle graph dimensions.
type Config struct {
	EdgeBits  uint
	ProofSize int
}

func (c Config) normalize() (Config, error) {
	if c.EdgeBits < 2 || c.EdgeBits > 31 {
		return Config{}, ErrInvalidEdgeBits
	}
	if c.ProofSize == 0 {
		c.ProofSize = ProofSize
	}
	if c.ProofSize < 2 || c.ProofSize > 255 {
		return Config{}, ErrInvalidProof
	}
	return c, nil
}

func (c Config) edgeMask() uint64 {
	return (uint64(1) << c.EdgeBits) - 1
}

func (c Config) nodeMask() uint64 {
	return c.edgeMask()
}

type Edge struct {
	U uint64
	V uint64
}

func sipRound(v *[4]uint64) {
	v[0] += v[1]
	v[1] = bits.RotateLeft64(v[1], 13)
	v[1] ^= v[0]
	v[0] = bits.RotateLeft64(v[0], 32)
	v[2] += v[3]
	v[3] = bits.RotateLeft64(v[3], 16)
	v[3] ^= v[2]
	v[0] += v[3]
	v[3] = bits.RotateLeft64(v[3], 21)
	v[3] ^= v[0]
	v[2] += v[1]
	v[1] = bits.RotateLeft64(v[1], 17)
	v[1] ^= v[2]
	v[2] = bits.RotateLeft64(v[2], 32)
}

func siphash24(seed [4]uint64, msg uint64) uint64 {
	// The MSC defines graph_seed as four little-endian 64-bit words k0..k3.
	// We treat those words as the seeded SipHash state directly.
	v := seed
	v[3] ^= msg
	sipRound(&v)
	sipRound(&v)
	v[0] ^= msg
	v[2] ^= 0xff
	for i := 0; i < 4; i++ {
		sipRound(&v)
	}
	return v[0] ^ v[1] ^ v[2] ^ v[3]
}

func seedWords(seed []byte) ([4]uint64, error) {
	var words [4]uint64
	if len(seed) != sha256.Size {
		return words, ErrInvalidSeed
	}
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(seed[i*8:])
	}
	return words, nil
}

// GraphSeed derives the 32-byte graph seed for a challenge and nonce.
//
// The caller must provide the canonicalized challenge bytes if canonical JSON
// semantics are required by a higher-level protocol.
func GraphSeed(challenge []byte, nonce uint64) [sha256.Size]byte {
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)
	buf := make([]byte, 0, len(challenge)+len(nonceBytes))
	buf = append(buf, challenge...)
	buf = append(buf, nonceBytes[:]...)
	return sha256.Sum256(buf)
}

// EdgeForNonce deterministically maps a nonce to a cuckoo edge.
func EdgeForNonce(cfg Config, seed []byte, nonce uint32) (Edge, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return Edge{}, err
	}
	words, err := seedWords(seed)
	if err != nil {
		return Edge{}, err
	}
	mask := cfg.nodeMask()
	u := siphash24(words, uint64(nonce)<<1) & mask
	v := siphash24(words, (uint64(nonce)<<1)|1) & mask
	return Edge{U: u, V: v}, nil
}

func Verify(cfg Config, seed []byte, nonces []uint32) error {
	cfg, err := cfg.normalize()
	if err != nil {
		return err
	}
	if len(nonces) != cfg.ProofSize {
		return ErrInvalidProof
	}
	if !slices.IsSorted(nonces) {
		return ErrInvalidProof
	}

	uvs := make([]uint64, 2*len(nonces))
	xor := uint64(0)
	for i, nonce := range nonces {
		if i > 0 && nonce == nonces[i-1] {
			return ErrInvalidProof
		}
		edge, err := EdgeForNonce(cfg, seed, nonce)
		if err != nil {
			return err
		}
		uvs[2*i] = edge.U << 1
		uvs[2*i+1] = (edge.V << 1) | 1
		xor ^= uvs[2*i]
		xor ^= uvs[2*i+1]
	}
	if xor != 0 {
		return ErrInvalidProof
	}

	n := 0
	i := 0
	for {
		j := i
		for k := 0; k < len(uvs); k += 2 {
			if k != i && uvs[k] == uvs[i] {
				if j != i {
					return ErrInvalidProof
				}
				j = k
			}
		}
		if j == i {
			return ErrInvalidProof
		}
		i = j ^ 1
		n++

		j = i
		for k := 1; k < len(uvs); k += 2 {
			if k != i && uvs[k] == uvs[i] {
				if j != i {
					return ErrInvalidProof
				}
				j = k
			}
		}
		if j == i {
			return ErrInvalidProof
		}
		i = j ^ 1
		n++

		if i == 0 {
			break
		}
	}
	if n != len(nonces) {
		return ErrInvalidProof
	}
	return nil
}

// bitset is a compact, fixed-size set of bits used in place of map[X]bool
// for the O(2^EdgeBits) and O(maxNonce) tracking arrays in FindProof. At
// production-scale parameters (EdgeBits=29) those sets have hundreds of
// millions of members; a Go map's per-entry bucket overhead would put total
// memory use in the tens of gigabytes where a bitset needs tens of
// megabytes.
type bitset []uint64

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
		aliveCount -= removedThisRound
		logf("cuckoo: trim round %d: -%d edges, %d alive (elapsed %s)", round+1, removedThisRound, aliveCount, time.Since(startTime).Round(time.Millisecond))
		// Diminishing returns: once a round clears under 0.1% of what's
		// left, further rounds aren't worth their fixed O(maxNonce) scan
		// cost — hand the remainder to the incremental peel instead.
		if removedThisRound == 0 || removedThisRound*1000 < aliveCount {
			break
		}
	}
	lo, hi = nil, nil

	type labeledEdge struct {
		nonce uint32
		u, v  uint64
	}

	survivors := make([]labeledEdge, 0, aliveCount)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		if !alive.get(uint64(nonce)) {
			continue
		}
		u, v := edgeEndpoints(nonce)
		survivors = append(survivors, labeledEdge{nonce: nonce, u: u, v: v})
	}
	alive = nil
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
		if edgeIdx == -1 {
			continue
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

	const dfsLogInterval = 200000
	for startIdx, start := range survivors {
		if removed[startIdx] {
			continue
		}
		if startIdx > 0 && startIdx%dfsLogInterval == 0 {
			logf("cuckoo: dfs: tried %d/%d starting edges (elapsed %s)", startIdx, len(survivors), time.Since(startTime).Round(time.Millisecond))
		}
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
