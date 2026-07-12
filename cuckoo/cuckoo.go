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

// FindProof performs a bounded search for a valid cycle. It is intended for
// tests and low-difficulty work factors, not production mining.
func FindProof(cfg Config, seed []byte, maxNonce uint32) ([]uint32, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return nil, err
	}

	type labeledEdge struct {
		nonce uint32
		u     uint64
		v     uint64
	}

	adj := map[uint64][]labeledEdge{}
	edges := make([]labeledEdge, 0, maxNonce)
	for nonce := uint32(0); nonce < maxNonce; nonce++ {
		edge, err := EdgeForNonce(cfg, seed, nonce)
		if err != nil {
			return nil, err
		}
		e := labeledEdge{
			nonce: nonce,
			u:     edge.U << 1,
			v:     (edge.V << 1) | 1,
		}
		edges = append(edges, e)
		adj[e.u] = append(adj[e.u], e)
		adj[e.v] = append(adj[e.v], e)
	}

	path := make([]uint32, 0, cfg.ProofSize)
	usedEdges := make([]bool, maxNonce)
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

		for _, next := range adj[currentNode] {
			if usedEdges[next.nonce] {
				continue
			}
			nextNode := next.u
			if nextNode == currentNode {
				nextNode = next.v
			}
			if nextNode != startNode && seenNodes[nextNode] {
				continue
			}
			usedEdges[next.nonce] = true
			seenNodes[nextNode] = true
			path = append(path, next.nonce)
			if proof, ok := dfs(startNode, nextNode, depth+1); ok {
				return proof, true
			}
			path = path[:len(path)-1]
			delete(seenNodes, nextNode)
			usedEdges[next.nonce] = false
		}
		return nil, false
	}

	for _, start := range edges {
		usedEdges[start.nonce] = true
		seenNodes[start.u] = true
		seenNodes[start.v] = true
		path = append(path[:0], start.nonce)
		if proof, ok := dfs(start.u, start.v, 1); ok {
			return proof, nil
		}
		usedEdges[start.nonce] = false
		delete(seenNodes, start.u)
		delete(seenNodes, start.v)
	}

	return nil, ErrNoSolution
}
