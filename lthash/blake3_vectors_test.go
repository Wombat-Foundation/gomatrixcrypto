package lthash

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// These pins are copied verbatim from rezzy's `blake3_lthash_vectors` test
// (src/state/lthash.rs), which covers the same BLAKE3 instantiation:
// expansion `BLAKE3(dst || element, 2048)`, collapse `BLAKE3(lattice)`, and the
// `msc4500:lthash16:blake3:v1` / `msc4500:redactions:blake3:v1` tags. A failure
// here means the Go and Rust implementations have diverged.

func b64u(sum [ChecksumLen]byte) string {
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestBlake3VectorEmptyAccumulator(t *testing.T) {
	// The empty accumulator still collapses to a real digest rather than a
	// special case, so a state that is empty and one that is merely
	// unresolved stay distinguishable from anything non-empty.
	var h Hash
	if got := h.String(); got != "viqN49z0bJTOhc3I4HrDCPTYqVSQ2VbDjXgP1hDbCBM" {
		t.Fatalf("empty accumulator digest: got %s", got)
	}
}

func TestBlake3Vectors(t *testing.T) {
	seed1 := seed("m.room.member", "@alice:example.com", "$event_1")
	seed1Bytes := seed1.Bytes()
	if got := hex.EncodeToString(seed1Bytes[:8]); got != "c3b425b048d36923" {
		t.Fatalf("seed1 lanes: got %s", got)
	}

	var s1 Hash
	s1.addSeed(seed1)
	s1Bytes := s1.Bytes()
	if got := hex.EncodeToString(s1Bytes[:16]); got != "c3b425b048d369230ec3b609c1f0c5a5" {
		t.Fatalf("s1 lanes: got %s", got)
	}
	if got := b64u(s1.Checksum()); got != "jkZrUIFtAvB1LEjCV0klBcoslgI_z-fy57tBaYhqy8g" {
		t.Fatalf("s1 digest: got %s", got)
	}

	seed2 := seed("m.room.name", "", "$event_2")
	seed2Bytes := seed2.Bytes()
	if got := hex.EncodeToString(seed2Bytes[:8]); got != "a6f3137486864ae3" {
		t.Fatalf("seed2 lanes: got %s", got)
	}

	s2 := s1
	s2.addSeed(seed2)
	s2Bytes := s2.Bytes()
	if got := hex.EncodeToString(s2Bytes[:16]); got != "69a83824ce59b3064470e993c77e73fe" {
		t.Fatalf("s2 lanes: got %s", got)
	}
	if got := b64u(s2.Checksum()); got != "0MOPtd797los_3q4fTJt4bKCjhRFZ12nwPEPshWDcEA" {
		t.Fatalf("s2 digest: got %s", got)
	}

	// Removing the first seed must land exactly back on the second state.
	seed3 := seed("m.room.member", "@alice:example.com", "$event_3")
	seed3Bytes := seed3.Bytes()
	if got := hex.EncodeToString(seed3Bytes[:8]); got != "2092781e84ce05bf" {
		t.Fatalf("seed3 lanes: got %s", got)
	}

	s3 := s2
	s3.subSeed(seed1)
	s3.addSeed(seed3)
	s3Bytes := s3.Bytes()
	if got := hex.EncodeToString(s3Bytes[:16]); got != "c6858b920a554fa224e1d928d63eceb7" {
		t.Fatalf("s3 lanes: got %s", got)
	}
	if got := b64u(s3.Checksum()); got != "BHYsmq2zHFAQZgQGlXuFqaAG9w9o7vFY7NkRcUL_554" {
		t.Fatalf("s3 digest: got %s", got)
	}

	back := s3
	back.subSeed(seed3)
	if got := b64u(back.Checksum()); got != "yeMXj6Fokw2iYonH8htoklFY5AwtcdDDnRGU_B79_2g" {
		t.Fatalf("back digest: got %s", got)
	}
}

func TestBlake3VectorRedactionOverlay(t *testing.T) {
	var one RedactionOverlay
	one.Insert("m.room.member", "@alice:example.org", "$state")
	oneDigest := one.Digest()
	if got := hex.EncodeToString(oneDigest[:]); got != "c18c12274627af27191a45b13755fff86b2567a871e30453e1bbeeeb436f2159" {
		t.Fatalf("one-entry overlay digest: got %s", got)
	}

	var two RedactionOverlay
	two.Insert("m.room.create", "", "$create")
	two.Insert("m.room.member", "@alice:example.org", "$state")
	twoDigest := two.Digest()
	if got := hex.EncodeToString(twoDigest[:]); got != "a572fff7e802aa93492e2c87bb50843b8da33bb29ff88177cda7067d08b0836f" {
		t.Fatalf("two-entry overlay digest: got %s", got)
	}

	var custom RedactionOverlay
	custom.Insert("org.example.custom", "key", "$custom")
	customDigest := custom.Digest()
	if got := hex.EncodeToString(customDigest[:]); got != "c2a2306f0728514669fb35e8d96046ab96ca7ed764edcefe6484fa563930019b" {
		t.Fatalf("custom overlay digest: got %s", got)
	}
}
