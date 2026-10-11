package lthash

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/zeebo/blake3"
)

// dstAESCTR is the MSC4500 primary accumulator domain tag for the AES-256-CTR
// instantiation. It is the same tag rezzy's expansion_backends.rs uses
// (DST_AES_CTR), so both implementations derive identical seeds; the
// ":aes-ctr:v1" suffix keeps these digests from ever matching the BLAKE3
// profile's.
var dstAESCTR = []byte("msc4500:lthash16:aes-ctr:v1")

// AESCTRHash is the MSC4500 primary accumulator expanded element-for-element
// with AES-256-CTR rather than the BLAKE3 XOF.
//
// It has exactly the lattice parameters of [Hash] — 1024 little-endian uint16
// lanes, element encoding as in MSC4500 §1, collapse via BLAKE3-256 of the
// serialized lattice — and differs only in how each element is expanded: the
// frame is hashed with BLAKE3 to a 32-byte key, and the 2048-byte seed is the
// AES-256 CTR keystream for counters 0..127. The distinct domain tag keeps the
// two profiles' element inputs disjoint, so a digest from one profile is never
// a digest produced by the other; it does not by itself prove two distinct
// element sets cannot collide.
//
// Callers must not mix the two: the value carries no record of which
// expansion produced it.
//
// On amd64 CPUs with AES-NI an Insert is allocation-free. Elsewhere the
// crypto/aes fallback heap-allocates a cipher block and a keystream buffer per
// element.
type AESCTRHash Hash

// seedAESCTR generates a lattice seed vector for an element under dstAESCTR.
//
// The framing is identical to [seedWithDST]; only the expansion primitive
// changes. It panics if writing the frame or reading the key fails.
func seedAESCTR(eventType, stateKey, eventID string) Hash {
	// key = BLAKE3-256(dst || element): the prefix of the same XOF stream
	// seedWithDST expands, cut to the cipher's key size.
	xof := blake3.New()
	writeElement(xof, dstAESCTR, eventType, stateKey, eventID)

	var key [32]byte
	if _, err := xof.Digest().Read(key[:]); err != nil {
		panic(err)
	}

	var buf [ByteSize]byte
	expandAES256Element(&key, buf[:])

	var out Hash
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return out
}

// Insert adds one entry to the accumulator.
// eventType and stateKey are truncated to at most 65535 bytes, preserving
// character boundaries for valid UTF-8; eventID is included in full.
func (h *AESCTRHash) Insert(eventType, stateKey, eventID string) {
	(*Hash)(h).addSeed(seedAESCTR(eventType, stateKey, eventID))
}

// Remove subtracts one entry from the accumulator.
func (h *AESCTRHash) Remove(eventType, stateKey, eventID string) {
	(*Hash)(h).subSeed(seedAESCTR(eventType, stateKey, eventID))
}

// Replace removes oldEventID and inserts newEventID for the same state entry.
func (h *AESCTRHash) Replace(eventType, stateKey, oldEventID, newEventID string) {
	h.Remove(eventType, stateKey, oldEventID)
	h.Insert(eventType, stateKey, newEventID)
}

// AESCTRFromEntries builds an AESCTRHash by inserting each provided entry.
func AESCTRFromEntries(entries []Entry) AESCTRHash {
	var h AESCTRHash
	for _, entry := range entries {
		h.Insert(entry.EventType, entry.StateKey, entry.EventID)
	}
	return h
}

// Bytes returns the raw 2048-byte lattice state encoding.
func (h AESCTRHash) Bytes() [ByteSize]byte {
	return Hash(h).Bytes()
}

// Checksum returns the BLAKE3-256 digest of the lattice state bytes.
func (h AESCTRHash) Checksum() [ChecksumLen]byte {
	return Hash(h).Checksum()
}

// String returns the hash checksum as unpadded base64url.
func (h AESCTRHash) String() string {
	sum := h.Checksum()
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
