// Package lthash implements MSC4500 LtHash16 state accumulators.
package lthash

import (
	"encoding/base64"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

const (
	// WordCount is the number of uint16 words in an LtHash16 state.
	WordCount = 1024
	// ByteSize is the byte length of a serialized LtHash16 state.
	ByteSize = WordCount * 2
	// ChecksumLen is the length of the LtHash16 checksum.
	ChecksumLen = 32
)

var dst = []byte("msc4500:lthash16:v1")
var readFull = io.ReadFull

// Hash is the 2048-byte LtHash16 lattice state.
type Hash [WordCount]uint16

// Entry identifies one state element in the lattice.
type Entry struct {
	// EventType is the Matrix event type.
	EventType string
	// StateKey is the Matrix state key.
	StateKey string
	// EventID is the event identifier included in the accumulator.
	EventID string
}

// truncateToU16Limit truncates string s to fit within a uint16 length.
func truncateToU16Limit(s string) (string, uint16) {
	if len(s) <= int(^uint16(0)) {
		return s, uint16(len(s))
	}
	end := int(^uint16(0))
	for end > 0 && (s[end]&0xC0) == 0x80 {
		end--
	}
	return s[:end], uint16(end)
}

// seedWithDST generates a lattice seed vector for an element and domain tag.
func seedWithDST(domain []byte, eventType, stateKey, eventID string) Hash {
	eventType, typeLen := truncateToU16Limit(eventType)
	stateKey, stateKeyLen := truncateToU16Limit(stateKey)

	xof := sha3.NewShake256()
	xof.Write(domain)

	var lens [2]byte
	binary.LittleEndian.PutUint16(lens[:], typeLen)
	xof.Write(lens[:])
	xof.Write([]byte(eventType))
	binary.LittleEndian.PutUint16(lens[:], stateKeyLen)
	xof.Write(lens[:])
	xof.Write([]byte(stateKey))
	xof.Write([]byte(eventID))

	var buf [ByteSize]byte
	if _, err := readFull(xof, buf[:]); err != nil {
		panic(err)
	}

	var out Hash
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return out
}

// seed generates the lattice seed vector for a state entry.
func seed(eventType, stateKey, eventID string) Hash {
	return seedWithDST(dst, eventType, stateKey, eventID)
}

// addSeed adds seed elementwise into h.
func (h *Hash) addSeed(seed Hash) {
	for i := range h {
		h[i] += seed[i]
	}
}

// subSeed subtracts seed elementwise from h.
func (h *Hash) subSeed(seed Hash) {
	for i := range h {
		h[i] -= seed[i]
	}
}

// Insert adds one entry to the hash.
func (h *Hash) Insert(eventType, stateKey, eventID string) {
	h.addSeed(seed(eventType, stateKey, eventID))
}

// Remove subtracts one entry from the hash.
func (h *Hash) Remove(eventType, stateKey, eventID string) {
	h.subSeed(seed(eventType, stateKey, eventID))
}

// Replace removes oldEventID and inserts newEventID for the same state entry.
func (h *Hash) Replace(eventType, stateKey, oldEventID, newEventID string) {
	h.subSeed(seed(eventType, stateKey, oldEventID))
	h.addSeed(seed(eventType, stateKey, newEventID))
}

// FromEntries builds a Hash by inserting each provided entry.
func FromEntries(entries []Entry) Hash {
	var h Hash
	for _, entry := range entries {
		h.Insert(entry.EventType, entry.StateKey, entry.EventID)
	}
	return h
}

// Bytes returns the raw 2048-byte lattice state encoding.
func (h Hash) Bytes() [ByteSize]byte {
	var out [ByteSize]byte
	for i, v := range h {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

// Checksum returns the BLAKE2b-256 checksum of the lattice state bytes.
func (h Hash) Checksum() [ChecksumLen]byte {
	bytes := h.Bytes()
	return blake2b.Sum256(bytes[:])
}

// String returns the hash checksum as unpadded base64url (the MSC4500 wire form).
func (h Hash) String() string {
	sum := h.Checksum()
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
