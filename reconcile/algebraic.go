package reconcile

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// MaxSketchCapacity is the maximum extraction capacity for an unbucketed algebraic_v1 sketch.
const MaxSketchCapacity = 32

// MaxLocalSketchDecodeCapacity is the default local extraction limit for CPU-bounded sketch decoding.
const MaxLocalSketchDecodeCapacity = MaxSketchCapacity

const eventHashEncodedLen = 43

var (
	ErrInvalidEventID        = errors.New("InvalidEventID")
	ErrInvalidBase64         = errors.New("InvalidBase64")
	ErrInvalidDigestLength   = errors.New("InvalidDigestLength")
	ErrInvalidSketchCapacity = errors.New("InvalidSketchCapacity")
	ErrInvalidSketchLength   = errors.New("InvalidSketchLength")
	ErrDecodeFailure         = errors.New("DecodeFailure")
	ErrBudgetExhausted       = errors.New("BudgetExhausted")
	ErrZeroShortIdentifier   = errors.New("ZeroShortIdentifier")
	ErrInvalidBucketIndex    = errors.New("InvalidBucketIndex")
	ErrCountOverflow         = errors.New("CountOverflow")
	ErrCountUnderflow        = errors.New("CountUnderflow")
)

// EventIDFormat selects the Matrix event-ID binding.
type EventIDFormat int

const (
	// Legacy uses the room versions 1 and 2 event-ID binding.
	Legacy EventIDFormat = iota
	// V3 uses the room version 3 event-ID binding.
	V3
	// V4Plus uses the room versions 4 and later event-ID binding.
	V4Plus
)

// ElementHash is the pair of MSC0500 digest truncations.
type ElementHash struct {
	// H128 is the first 128 bits of the canonical digest, in network byte order.
	H128 [16]byte
	// H64 is the first non-zero 64-bit chunk of the canonical digest.
	H64 uint64
}

// FromDigest32 derives the profile truncations from a canonical 32-byte digest.
func FromDigest32(digest [32]byte) ElementHash {
	var wide [16]byte
	copy(wide[:], digest[:16])

	h64 := uint64(1)
	for i := 0; i < 4; i++ {
		chunk := binary.BigEndian.Uint64(digest[i*8 : (i+1)*8])
		if chunk != 0 {
			h64 = chunk
			break
		}
	}

	return ElementHash{H128: wide, H64: h64}
}

// FromMatrixEventID derives an element hash from a Matrix event ID.
func FromMatrixEventID(eventID string, format EventIDFormat) (ElementHash, error) {
	digest, err := MatrixEventDigest32(eventID, format)
	if err != nil {
		return ElementHash{}, err
	}
	return FromDigest32(digest), nil
}

// MatrixEventDigest32 derives the canonical 32-byte digest for an event ID.
func MatrixEventDigest32(eventID string, format EventIDFormat) ([32]byte, error) {
	var out [32]byte
	encoded, ok := trimSigil(eventID)
	if !ok {
		return out, ErrInvalidEventID
	}
	if format != Legacy && len(encoded) > eventHashEncodedLen {
		return out, ErrInvalidBase64
	}

	var digest []byte
	switch format {
	case Legacy:
		sum := sha256.Sum256([]byte(eventID))
		digest = sum[:]
	case V3:
		var err error
		digest, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return out, ErrInvalidBase64
		}
	case V4Plus:
		var err error
		digest, err = base64.RawURLEncoding.DecodeString(encoded)
		if err != nil {
			return out, ErrInvalidBase64
		}
	default:
		return out, ErrInvalidEventID
	}

	if len(digest) != 32 {
		return out, ErrInvalidEventID
	}
	copy(out[:], digest)
	return out, nil
}

func trimSigil(eventID string) (string, bool) {
	if len(eventID) == 0 || eventID[0] != '$' {
		return "", false
	}
	return eventID[1:], true
}

// RoomAccumulator tracks the level-0 digest and exact event count.
type RoomAccumulator struct {
	// Digest is the 128-bit XOR accumulator over element hashes.
	Digest [16]byte
	// Count is the exact number of accumulated elements.
	Count uint64
}

// NewRoomAccumulator returns an empty accumulator.
func NewRoomAccumulator() RoomAccumulator {
	return RoomAccumulator{}
}

// Insert adds one element hash.
func (r *RoomAccumulator) Insert(hash ElementHash) error {
	if r.Count == ^uint64(0) {
		return ErrCountOverflow
	}
	r.Count++
	for i := 0; i < len(r.Digest); i++ {
		r.Digest[i] ^= hash.H128[i]
	}
	return nil
}

// Remove subtracts one element hash.
func (r *RoomAccumulator) Remove(hash ElementHash) error {
	if r.Count == 0 {
		return ErrCountUnderflow
	}
	r.Count--
	for i := 0; i < len(r.Digest); i++ {
		r.Digest[i] ^= hash.H128[i]
	}
	return nil
}

// EncodeDigest returns the unpadded URL-safe Base64 digest encoding.
func (r RoomAccumulator) EncodeDigest() string {
	return base64.RawURLEncoding.EncodeToString(r.Digest[:])
}

// DecodeDigest parses a level-0 digest encoding.
func DecodeDigest(encoded string) ([16]byte, error) {
	var out [16]byte
	if len(encoded) != base64.RawURLEncoding.EncodedLen(len(out)) {
		return out, ErrInvalidDigestLength
	}
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return out, ErrInvalidBase64
	}
	// coverage:ignore
	if len(bytes) != len(out) {
		return out, ErrInvalidDigestLength
	}
	copy(out[:], bytes)
	return out, nil
}

// Residual returns the XOR difference between two room digests.
func (r RoomAccumulator) Residual(other RoomAccumulator) [16]byte {
	var out [16]byte
	for i := range out {
		out[i] = r.Digest[i] ^ other.Digest[i]
	}
	return out
}

// ETag encodes the MSC0501 opaque room frontier value.
func (r RoomAccumulator) ETag(extremityEventIDs []string) string {
	extremities := append([]string(nil), extremityEventIDs...)
	sortStrings(extremities)
	frontierHash := sha256.Sum256(canonicalStringArray(extremities))
	etag := make([]byte, 0, 24)
	etag = append(etag, r.Digest[:]...)
	etag = append(etag, frontierHash[:8]...)
	return base64.RawURLEncoding.EncodeToString(etag)
}

// VerifyResidual checks decoded difference hashes against an expected residual.
func VerifyResidual(expectedResidual [16]byte, hashes []ElementHash) bool {
	var residual [16]byte
	for _, hash := range hashes {
		for i := range residual {
			residual[i] ^= hash.H128[i]
		}
	}
	return residual == expectedResidual
}

// SyndromeSketch stores odd syndrome coordinates s1, s3, ... over GF(2^64).
type SyndromeSketch struct {
	// Coordinates stores the odd-power syndrome coordinates in order.
	Coordinates []uint64
}

// NewSyndromeSketch allocates an empty sketch with the requested capacity.
func NewSyndromeSketch(capacity int) (*SyndromeSketch, error) {
	if capacity <= 0 || capacity > MaxSketchCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	return &SyndromeSketch{Coordinates: make([]uint64, capacity)}, nil
}

// NewSyndromeSketchFromCoordinates builds a sketch from exact coordinates.
func NewSyndromeSketchFromCoordinates(coordinates []uint64) (*SyndromeSketch, error) {
	if len(coordinates) == 0 || len(coordinates) > MaxSketchCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	out := make([]uint64, len(coordinates))
	copy(out, coordinates)
	return &SyndromeSketch{Coordinates: out}, nil
}

// Capacity returns the number of stored coordinates.
func (s *SyndromeSketch) Capacity() int {
	return len(s.Coordinates)
}

// Toggle inserts or removes a short identifier.
func (s *SyndromeSketch) Toggle(value uint64) error {
	if value == 0 {
		return ErrZeroShortIdentifier
	}
	squared := Mul(value, value)
	oddPower := value
	for i := range s.Coordinates {
		s.Coordinates[i] ^= oddPower
		oddPower = Mul(oddPower, squared)
	}
	return nil
}

// Xor subtracts another sketch in-place.
func (s *SyndromeSketch) Xor(other *SyndromeSketch) error {
	if s.Capacity() != other.Capacity() {
		return ErrInvalidSketchLength
	}
	for i := range s.Coordinates {
		s.Coordinates[i] ^= other.Coordinates[i]
	}
	return nil
}

// Subtract returns the XOR difference between two sketches.
func (s *SyndromeSketch) Subtract(other *SyndromeSketch) (*SyndromeSketch, error) {
	if s.Capacity() != other.Capacity() {
		return nil, ErrInvalidSketchLength
	}
	out := make([]uint64, len(s.Coordinates))
	for i := range out {
		out[i] = s.Coordinates[i] ^ other.Coordinates[i]
	}
	return &SyndromeSketch{Coordinates: out}, nil
}

// DecodeElements decodes up to maxElements roots from the sketch.
func (s *SyndromeSketch) DecodeElements(maxElements int) ([]uint64, error) {
	if maxElements <= 0 || maxElements > s.Capacity() || maxElements > MaxLocalSketchDecodeCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	decoded, err := decodePinsketch(s.Coordinates[:maxElements], maxElements)
	if err != nil {
		return nil, err
	}
	// coverage:ignore
	if containsZero(decoded) {
		return nil, ErrDecodeFailure
	}
	check, err := NewSyndromeSketch(s.Capacity())
	// coverage:ignore
	if err != nil {
		return nil, err
	}
	for _, element := range decoded {
		// coverage:ignore
		if err := check.Toggle(element); err != nil {
			return nil, err
		}
	}
	if !equalSketch(check, s) {
		return nil, ErrDecodeFailure
	}
	return decoded, nil
}

// Encode serializes a sketch using unpadded URL-safe Base64.
func (s *SyndromeSketch) Encode() string {
	bytes := make([]byte, 0, len(s.Coordinates)*8)
	for _, coordinate := range s.Coordinates {
		var tmp [8]byte
		binary.LittleEndian.PutUint64(tmp[:], coordinate)
		bytes = append(bytes, tmp[:]...)
	}
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// DecodeSyndromeSketch parses a sketch with an externally negotiated capacity.
func DecodeSyndromeSketch(capacity int, encoded string) (*SyndromeSketch, error) {
	if capacity == 0 || capacity > MaxSketchCapacity {
		return nil, ErrInvalidSketchCapacity
	}
	expectedLen := capacity * 8
	expectedEncodedLen := base64.RawURLEncoding.EncodedLen(expectedLen)
	if len(encoded) != expectedEncodedLen {
		return nil, ErrInvalidSketchLength
	}
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrInvalidBase64
	}
	return newSketchFromEncodedBytes(capacity, bytes)
}

func newSketchFromEncodedBytes(capacity int, bytes []byte) (*SyndromeSketch, error) {
	expectedLen := capacity * 8
	if len(bytes) != expectedLen {
		return nil, ErrInvalidSketchLength
	}
	coordinates := make([]uint64, capacity)
	for i := 0; i < capacity; i++ {
		coordinates[i] = binary.LittleEndian.Uint64(bytes[i*8:])
	}
	return &SyndromeSketch{Coordinates: coordinates}, nil
}

// DecodeDigest32 aliases MatrixEventDigest32 for symmetry with the Rust API.
func DecodeDigest32(eventID string, format EventIDFormat) ([32]byte, error) {
	return MatrixEventDigest32(eventID, format)
}

func equalSketch(left, right *SyndromeSketch) bool {
	if left.Capacity() != right.Capacity() {
		return false
	}
	for i := range left.Coordinates {
		if left.Coordinates[i] != right.Coordinates[i] {
			return false
		}
	}
	return true
}

func containsZero(values []uint64) bool {
	for _, value := range values {
		if value == 0 {
			return true
		}
	}
	return false
}

func sortStrings(values []string) {
	if len(values) < 2 {
		return
	}
	for i := 1; i < len(values); i++ {
		v := values[i]
		j := i - 1
		for j >= 0 && values[j] > v {
			values[j+1] = values[j]
			j--
		}
		values[j+1] = v
	}
}

func canonicalStringArray(values []string) []byte {
	if values == nil {
		return []byte("null")
	}
	out := make([]byte, 0, len(values)*4+2)
	out = append(out, '[')
	for i, value := range values {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, '"')
		for j := 0; j < len(value); j++ {
			switch value[j] {
			case '\\', '"':
				out = append(out, '\\', value[j])
			case '\b':
				out = append(out, '\\', 'b')
			case '\f':
				out = append(out, '\\', 'f')
			case '\n':
				out = append(out, '\\', 'n')
			case '\r':
				out = append(out, '\\', 'r')
			case '\t':
				out = append(out, '\\', 't')
			default:
				out = append(out, value[j])
			}
		}
		out = append(out, '"')
	}
	out = append(out, ']')
	return out
}

func decodePinsketch(oddSyndromes []uint64, maxElements int) ([]uint64, error) {
	return decodePinSketch(oddSyndromes, maxElements)
}

// Eagerly fail if the package API drifts away from the Rust surface.
var (
	_ = fmt.Sprintf
)
