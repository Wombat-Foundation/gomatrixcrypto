// Package cuckoo implements Cuckatoo Cycle proof derivation and verification.
package cuckoo

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/bits"
	"slices"
)

// ProofSize is the default number of edges in a Cuckoo Cycle proof.
const ProofSize = 42

var (
	// ErrInvalidEdgeBits reports an out-of-range edge-bit configuration.
	ErrInvalidEdgeBits = errors.New("edge bits out of range")
	// ErrInvalidSeed reports a graph seed with the wrong length.
	ErrInvalidSeed = errors.New("invalid graph seed")
	// ErrInvalidProof reports a malformed or invalid proof.
	ErrInvalidProof = errors.New("invalid cuckoo cycle proof")
	// ErrNoSolution reports that proof search found no valid cycle.
	ErrNoSolution = errors.New("no cycle found")
)

// Config defines the cycle graph dimensions.
type Config struct {
	// EdgeBits is the number of bits in each graph node index.
	EdgeBits uint
	// ProofSize is the expected number of edges in a valid proof.
	ProofSize int
}

// Validate checks whether the configuration graph dimensions are valid.
func (c Config) Validate() error {
	_, err := c.normalize()
	return err
}

// normalize validates and fills default values for Config.
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

// EdgeMask returns the bitmask for edge indices given EdgeBits.
func (c Config) EdgeMask() uint64 {
	return (uint64(1) << c.EdgeBits) - 1
}

// edgeMask returns EdgeMask for the configuration.
func (c Config) edgeMask() uint64 {
	return c.EdgeMask()
}

// nodeMask returns the bitmask for graph nodes.
func (c Config) nodeMask() uint64 {
	return c.edgeMask()
}

// Edge identifies one graph edge by its U and V endpoints.
type Edge struct {
	// U is the U-side endpoint of the edge.
	U uint64
	// V is the V-side endpoint of the edge.
	V uint64
}

// sipRound performs one round of the SipHash-2-4 mixing function.
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

// siphash24 calculates 64-bit SipHash-2-4 output for a message.
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

// seedWords converts a 32-byte graph seed into four uint64 words.
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

// EdgeForNonce deterministically maps an edge index to a cuckoo edge.
func EdgeForNonce(cfg Config, seed []byte, edgeIdx uint32) (Edge, error) {
	cfg, err := cfg.normalize()
	if err != nil {
		return Edge{}, err
	}
	if uint64(edgeIdx) > cfg.edgeMask() {
		return Edge{}, ErrInvalidProof
	}
	words, err := seedWords(seed)
	if err != nil {
		return Edge{}, err
	}
	mask := cfg.nodeMask()
	u := siphash24(words, uint64(edgeIdx)<<1) & mask
	v := siphash24(words, (uint64(edgeIdx)<<1)|1) & mask
	return Edge{U: u, V: v}, nil
}

// Verify checks that nonces form a valid Cuckoo Cycle proof for cfg and seed.
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
	for i, nonce := range nonces {
		if i > 0 && nonce == nonces[i-1] {
			return ErrInvalidProof
		}
		if uint64(nonce) > cfg.edgeMask() {
			return ErrInvalidProof
		}
		edge, err := EdgeForNonce(cfg, seed, nonce)
		if err != nil {
			return err
		}
		uvs[2*i] = edge.U << 1
		uvs[2*i+1] = (edge.V << 1) | 1
	}
	return verifyCycle(uvs)
}

// verifyCycle checks that tagged endpoints form exactly one cycle. Its input
// is internal and has already been range-checked by Verify.
// verifyCycle verifies that the specified endpoint pairs form a single cycle.
func verifyCycle(uvs []uint64) error {
	xor := uint64(0)
	for _, endpoint := range uvs {
		xor ^= endpoint
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
	if n != len(uvs)/2 {
		return ErrInvalidProof
	}
	return nil
}
