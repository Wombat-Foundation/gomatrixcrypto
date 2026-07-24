// Package cuckoo implements Cuckoo Cycle proof derivation and verification.
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

// Edge identifies one graph edge by its U and V endpoints.
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
