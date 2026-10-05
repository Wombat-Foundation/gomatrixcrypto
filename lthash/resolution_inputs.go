package lthash

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"sort"

	"github.com/zeebo/blake3"
)

var resolutionInputsDST = []byte("msc4500:resolution_inputs:blake3:v1")

// ResolutionInputRecord is one labelled element of the MSC4500 resolution-input
// set I(P): an event together with its outgoing auth_events and
// prev_state_events edges. The same EventID with different edges is a distinct
// element.
type ResolutionInputRecord struct {
	EventID    string
	EventType  string
	StateKey   string
	AuthEvents []string
	// StatePredecessors is prev_state_events; empty for room versions that do
	// not define it.
	StatePredecessors []string
}

// Encode serializes the record as specified by MSC4500:
//
//	len(event_id) || event_id || len(type) || type || len(state_key) ||
//	state_key || auth_events || state_predecessors
//
// Each len is uint16le. An ID list is uint32le(count) followed by its IDs in
// bytewise ascending order, each as uint16le(length) || id.
func (r ResolutionInputRecord) Encode() []byte {
	var out bytes.Buffer
	putString(&out, r.EventID)
	putString(&out, r.EventType)
	putString(&out, r.StateKey)
	putIDs(&out, r.AuthEvents)
	putIDs(&out, r.StatePredecessors)
	return out.Bytes()
}

func putString(out *bytes.Buffer, s string) {
	s, n := truncateToU16Limit(s)
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], n)
	out.Write(l[:])
	out.WriteString(s)
}

func putIDs(out *bytes.Buffer, ids []string) {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], uint32(len(sorted)))
	out.Write(c[:])
	for _, id := range sorted {
		putString(out, id)
	}
}

// ResolutionInputs is the MSC4500 diagnostic accumulator over the labelled
// state-resolution input set. It uses the same lattice parameters as Hash under
// a separate domain-separation tag. Callers must supply a set: each distinct
// record exactly once, however many paths reach it.
type ResolutionInputs Hash

func resolutionSeed(r ResolutionInputRecord) Hash {
	xof := blake3.New()
	if _, err := xof.Write(resolutionInputsDST); err != nil {
		panic(err)
	}
	if _, err := xof.Write(r.Encode()); err != nil {
		panic(err)
	}

	var buf [ByteSize]byte
	if _, err := readFull(xof.Digest(), buf[:]); err != nil {
		panic(err)
	}
	var out Hash
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return out
}

// Insert adds one labelled input record.
func (o *ResolutionInputs) Insert(r ResolutionInputRecord) {
	s := resolutionSeed(r)
	for i := range o {
		o[i] += s[i]
	}
}

// Remove subtracts one previously inserted record.
func (o *ResolutionInputs) Remove(r ResolutionInputRecord) {
	s := resolutionSeed(r)
	for i := range o {
		o[i] -= s[i]
	}
}

// Digest returns the BLAKE3-256 digest of the lattice.
func (o ResolutionInputs) Digest() [ChecksumLen]byte {
	h := Hash(o)
	return h.Checksum()
}

// String returns the digest as unpadded base64url.
func (o ResolutionInputs) String() string {
	sum := o.Digest()
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
