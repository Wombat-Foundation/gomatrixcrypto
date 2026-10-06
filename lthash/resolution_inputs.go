package lthash

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/zeebo/blake3"
)

var resolutionInputsDST = []byte("msc4500:resolution_inputs:blake3:v1")

// ErrResolutionInputTooLong reports a resolution-input field or ID that does
// not fit the uint16le length prefix MSC4500's record encoding requires.
var ErrResolutionInputTooLong = errors.New("lthash: resolution input exceeds 65535 bytes")

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
// bytewise ascending order, each as uint16le(length) || id. A field or ID
// longer than 65535 bytes is rejected with an error wrapping
// ErrResolutionInputTooLong rather than truncated, which would let distinct
// inputs encode identically. ID lists are not modified or deduplicated.
func (r ResolutionInputRecord) Encode() ([]byte, error) {
	var out bytes.Buffer
	for _, s := range []string{r.EventID, r.EventType, r.StateKey} {
		if err := putString(&out, s); err != nil {
			return nil, err
		}
	}
	if err := putIDs(&out, r.AuthEvents); err != nil {
		return nil, err
	}
	if err := putIDs(&out, r.StatePredecessors); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// putString appends s with a uint16le byte-length prefix. If s exceeds 65535
// bytes, it leaves out unchanged and returns an error wrapping
// ErrResolutionInputTooLong.
func putString(out *bytes.Buffer, s string) error {
	if len(s) > int(^uint16(0)) {
		return fmt.Errorf("%w: %d bytes", ErrResolutionInputTooLong, len(s))
	}
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(s)))
	out.Write(l[:])
	out.WriteString(s)
	return nil
}

// putIDs appends a uint32le count and length-prefixed IDs in bytewise ascending
// order, retaining duplicates and leaving ids unchanged. It propagates
// putString errors; out retains the count and any IDs already written.
func putIDs(out *bytes.Buffer, ids []string) error {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	var c [4]byte
	binary.LittleEndian.PutUint32(c[:], uint32(len(sorted)))
	out.Write(c[:])
	for _, id := range sorted {
		if err := putString(out, id); err != nil {
			return err
		}
	}
	return nil
}

// ResolutionInputs is the MSC4500 diagnostic accumulator over the labelled
// state-resolution input set. It uses the same lattice parameters as Hash under
// a separate domain-separation tag. Callers must supply a set: each distinct
// record exactly once, however many paths reach it.
type ResolutionInputs Hash

// resolutionSeed derives the resolution-input lattice seed from r's encoding.
// It returns a zero Hash and any Encode error, and panics if writing to or
// reading from the XOF fails.
func resolutionSeed(r ResolutionInputRecord) (Hash, error) {
	encoded, err := r.Encode()
	if err != nil {
		return Hash{}, err
	}

	xof := blake3.New()
	mustWrite(xof, resolutionInputsDST)
	mustWrite(xof, encoded)

	var buf [ByteSize]byte
	if _, err := readFull(xof.Digest(), buf[:]); err != nil {
		panic(err)
	}
	var out Hash
	for i := range out {
		out[i] = binary.LittleEndian.Uint16(buf[i*2:])
	}
	return out, nil
}

// Insert adds one labelled input record. It reports ErrResolutionInputTooLong
// if a field or ID exceeds the encoding's uint16le length prefix.
// On error, the accumulator is unchanged.
func (o *ResolutionInputs) Insert(r ResolutionInputRecord) error {
	s, err := resolutionSeed(r)
	if err != nil {
		return err
	}
	for i := range o {
		o[i] += s[i]
	}
	return nil
}

// Remove subtracts one previously inserted record. It reports
// ErrResolutionInputTooLong if a field or ID exceeds the encoding's uint16le
// length prefix.
// It does not check membership. On error, the accumulator is unchanged.
func (o *ResolutionInputs) Remove(r ResolutionInputRecord) error {
	s, err := resolutionSeed(r)
	if err != nil {
		return err
	}
	for i := range o {
		o[i] -= s[i]
	}
	return nil
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
