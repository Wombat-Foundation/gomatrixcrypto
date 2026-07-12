package cuckoo

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"
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
	return c.edgeMask() >> 1
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

// FindProof performs a bounded search for a valid cycle.
//
// It uses the usual Cuckoo Cycle first step: trim edges attached to leaf nodes
// before doing any path search. This is still a compact CPU helper, not a
// competitive production miner.
//
// Graph state is kept in flat, node-indexed arrays (a CSR adjacency list)
// rather than maps, since maps over O(2^EdgeBits) keys are what made larger
// EdgeBits configurations (e.g. the production profile's EdgeBits=29)
// allocate tens of gigabytes of map bucket overhead.
func FindProof(cfg Config, seed []byte, maxNonce uint32) ([]uint32, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	words, err := seedWords(seed)
	if err != nil {
		return nil, err
	}

	type graphEdge struct {
		u, v uint32
	}

	numEdges := uint64(maxNonce)
	nodeCount := uint64(1) << cfg.EdgeBits
	mask := cfg.nodeMask()

	// An edge's nonce equals its index in edges: both are assigned in the
	// same 0..maxNonce-1 sequence below, so it never needs its own field.
	edges := make([]graphEdge, maxNonce)
	degrees := make([]uint32, nodeCount)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		u := uint32((siphash24(words, uint64(nonce)<<1) & mask) << 1)
		v := uint32(((siphash24(words, (uint64(nonce)<<1)|1) & mask) << 1) | 1)
		edges[nonce] = graphEdge{u: u, v: v}
		degrees[u]++
		degrees[v]++
	}

	// incidentOffset[n]:incidentOffset[n+1] slices incidentEdges into the
	// edge indices touching node n (a standard CSR adjacency list).
	incidentOffset := make([]uint32, nodeCount+1)
	for n := uint64(0); n < nodeCount; n++ {
		incidentOffset[n+1] = incidentOffset[n] + degrees[n]
	}
	incidentEdges := make([]uint32, incidentOffset[nodeCount])
	// incidentOffset[0:nodeCount] is reused as a write cursor while filling,
	// then unshifted back into start offsets — this avoids a second
	// nodeCount-sized array just to track fill positions.
	for idx, e := range edges {
		incidentEdges[incidentOffset[e.u]] = uint32(idx)
		incidentOffset[e.u]++
		incidentEdges[incidentOffset[e.v]] = uint32(idx)
		incidentOffset[e.v]++
	}
	for n := nodeCount; n > 0; n-- {
		incidentOffset[n] = incidentOffset[n-1]
	}
	incidentOffset[0] = 0

	removed := newBitset(numEdges)
	queue := make([]uint32, 0, 64)
	for n := uint64(0); n < nodeCount; n++ {
		if degrees[n] == 1 {
			queue = append(queue, uint32(n))
		}
	}

	for head := 0; head < len(queue); head++ {
		node := queue[head]
		if degrees[node] != 1 {
			continue
		}

		edgeIdx := ^uint32(0)
		for _, idx := range incidentEdges[incidentOffset[node]:incidentOffset[node+1]] {
			if !removed.get(uint64(idx)) {
				edgeIdx = idx
				break
			}
		}
		if edgeIdx == ^uint32(0) {
			continue
		}

		removed.set(uint64(edgeIdx))
		edge := edges[edgeIdx]
		for _, endpoint := range [...]uint32{edge.u, edge.v} {
			degrees[endpoint]--
			if degrees[endpoint] == 1 {
				queue = append(queue, endpoint)
			}
		}
	}

	path := make([]uint32, 0, cfg.ProofSize)
	usedEdges := newBitset(numEdges)
	seenNodes := newBitset(nodeCount)
	var dfs func(startNode, currentNode uint32, depth int) ([]uint32, bool)

	dfs = func(startNode, currentNode uint32, depth int) ([]uint32, bool) {
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

		for _, nextIdx := range incidentEdges[incidentOffset[currentNode]:incidentOffset[currentNode+1]] {
			if removed.get(uint64(nextIdx)) || usedEdges.get(uint64(nextIdx)) {
				continue
			}
			next := edges[nextIdx]
			nextNode := next.u
			if nextNode == currentNode {
				nextNode = next.v
			}
			if nextNode != startNode && seenNodes.get(uint64(nextNode)) {
				continue
			}
			usedEdges.set(uint64(nextIdx))
			seenNodes.set(uint64(nextNode))
			path = append(path, nextIdx)
			if proof, ok := dfs(startNode, nextNode, depth+1); ok {
				return proof, true
			}
			path = path[:len(path)-1]
			seenNodes.clear(uint64(nextNode))
			usedEdges.clear(uint64(nextIdx))
		}
		return nil, false
	}

	for startIdx := range edges {
		if removed.get(uint64(startIdx)) {
			continue
		}
		start := edges[startIdx]
		usedEdges.set(uint64(startIdx))
		seenNodes.set(uint64(start.u))
		seenNodes.set(uint64(start.v))
		path = append(path[:0], uint32(startIdx))
		if proof, ok := dfs(start.u, start.v, 1); ok {
			return proof, nil
		}
		usedEdges.clear(uint64(startIdx))
		seenNodes.clear(uint64(start.u))
		seenNodes.clear(uint64(start.v))
	}

	return nil, ErrNoSolution
}
