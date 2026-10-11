package lthash

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

// This file implements the AES-256-CTR element expansion candidate from
// rezzy's benches/math/expansion_backends.rs: the MSC4500 element frame is
// hashed to a 32-byte BLAKE3 key, and the 2048-byte seed is the CTR keystream
// block i = AES-256(key, be128(i)) for i in [0, 128). It is a drop-in
// replacement for the BLAKE3 XOF in [seedWithDST], under its own domain tag,
// so the two accumulator families can never produce the same digests.

const (
	// aesKeyBytes is an AES-256 round-key schedule: 15 keys x 16 bytes, each
	// stored big-endian so the AES-NI unit loads it straight from memory.
	aesKeyBytes = 240
	// aesElementBlocks is the number of AES blocks in one lattice element.
	aesElementBlocks = ByteSize / aes.BlockSize
)

// aesSBox is the AES substitution box, built once from the affine transform
// over GF(2^8) rather than pasted as a 256-byte constant.
var aesSBox [256]byte

// aesCtrInput holds the block inputs for one element: block i is the 128-bit
// big-endian counter i. The element size is fixed, so the template is built
// once at init and reused rather than regenerated per insert.
var aesCtrInput [ByteSize]byte

// aesZeroInput is the all-zero plaintext the portable fallback XORs the
// keystream onto, so both paths leave the raw keystream behind.
var aesZeroInput [ByteSize]byte

func init() {
	buildAES256SBox()
	for i := 0; i < aesElementBlocks; i++ {
		binary.BigEndian.PutUint64(aesCtrInput[i*aes.BlockSize+8:], uint64(i))
	}
}

// buildAES256SBox fills aesSBox with the AES affine transform of the
// multiplicative inverse in GF(2^8).
func buildAES256SBox() {
	p, q := byte(1), byte(1)
	for {
		orig := p
		p = orig ^ (orig << 1)
		if orig&0x80 != 0 {
			p ^= 0x1b
		}

		q ^= q << 1
		q ^= q << 2
		q ^= q << 4
		if q&0x80 != 0 {
			q ^= 0x09
		}

		x := q ^ rotl8(q, 1) ^ rotl8(q, 2) ^ rotl8(q, 3) ^ rotl8(q, 4)
		aesSBox[p] = x ^ 0x63

		if p == 1 {
			break
		}
	}
	aesSBox[0] = 0x63
}

func rotl8(v byte, n uint) byte { return v<<n | v>>(8-n) }

func xtime(b byte) byte {
	if b&0x80 != 0 {
		return b<<1 ^ 0x1b
	}
	return b << 1
}

func subWord(w uint32) uint32 {
	return uint32(aesSBox[byte(w>>24)])<<24 |
		uint32(aesSBox[byte(w>>16)])<<16 |
		uint32(aesSBox[byte(w>>8)])<<8 |
		uint32(aesSBox[byte(w)])
}

// expandAES256Key expands a 32-byte AES-256 key into rk, a 240-byte schedule
// laid out exactly as the AES-NI round keys expect it.
func expandAES256Key(key *[32]byte, rk *[aesKeyBytes]byte) {
	var w [60]uint32
	for i := 0; i < 8; i++ {
		w[i] = binary.BigEndian.Uint32(key[4*i:])
	}
	rcon := byte(1)
	for i := 8; i < 60; i++ {
		t := w[i-1]
		switch i & 7 {
		case 0:
			t = subWord(t<<8|t>>24) ^ uint32(rcon)<<24
			rcon = xtime(rcon)
		case 4:
			t = subWord(t)
		}
		w[i] = w[i-8] ^ t
	}
	for i, v := range w {
		binary.BigEndian.PutUint32(rk[4*i:], v)
	}
}

// expandAES256Element writes one lattice element: out[i] is
// AES-256(key, be128(i/blockSize)).
//
// On amd64 CPUs with AES-NI it runs the hand-written block loop, which keeps
// the round keys on the stack and allocates nothing, so the accumulator path
// that calls this is allocation-free. Elsewhere it falls back to crypto/aes,
// whose keyed cipher block and 2048-byte keystream buffer are heap-allocated
// per element.
func expandAES256Element(key *[32]byte, out []byte) {
	if len(out) != ByteSize {
		panic("aes-ctr expansion: element must be 2048 bytes")
	}
	if !aesHardwareExpand(key, out) {
		expandAES256Stdlib(key, out)
	}
}

// expandAES256Stdlib is the portable fallback: crypto/aes CTR with a zero IV.
// The keystream is built in its own buffer so out stays non-escaping even
// though cipher.Stream is an interface call.
func expandAES256Stdlib(key *[32]byte, out []byte) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err)
	}
	ks := make([]byte, ByteSize)
	cipher.NewCTR(block, aesCtrInput[:aes.BlockSize]).XORKeyStream(ks, aesZeroInput[:])
	copy(out, ks)
}
