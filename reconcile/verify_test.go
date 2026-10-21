package reconcile

import (
	"encoding/binary"
	"testing"
)

// testElement carries the three digest truncations of one test element.
type testElement struct {
	h64  uint64
	q3   uint64
	h128 [16]byte
}

// digest reconstructs the canonical 32-byte digest for the element, so
// VerifyFollowUp derives H64/H128 itself from these bytes.
func (e testElement) digest() [32]byte {
	var d [32]byte
	binary.BigEndian.PutUint64(d[0:8], e.h64)
	binary.BigEndian.PutUint64(d[8:16], e.q3)
	copy(d[16:], e.h128[:])
	return d
}

func element(h64 uint64, h128Byte byte) testElement {
	var h128 [16]byte
	h128[0] = h128Byte
	return testElement{h64: h64, q3: h64, h128: h128}
}

func lookup(local []testElement) func(uint64) [][16]byte {
	return func(root uint64) [][16]byte {
		var candidates [][16]byte
		for _, e := range local {
			if e.h64 == root {
				candidates = append(candidates, e.h128)
			}
		}
		return candidates
	}
}

func summarize(set []testElement) NodeSummary {
	var summary NodeSummary
	for _, e := range set {
		summary.Count++
		for i := range summary.Digest {
			summary.Digest[i] ^= e.h128[i]
		}
	}
	return summary
}

func TestVerifyDecodeHonestDifferencePassesBothPhases(t *testing.T) {
	shared := element(1, 0x10)
	l := element(2, 0x20)
	m := element(3, 0x40)
	local := []testElement{shared, l}
	remote := []testElement{shared, m}

	classified, ok := VerifyDecode(
		BucketRequest{Depth: 0, Prefix: 0, Capacity: 8},
		summarize(local), summarize(remote),
		[]uint64{2, 3},
		lookup(local),
	)
	if !ok {
		t.Fatal("honest difference failed phase 1")
	}
	if len(classified.LRoots) != 1 || classified.LRoots[0] != 2 {
		t.Fatalf("L roots = %v, want [2]", classified.LRoots)
	}
	if len(classified.MRoots) != 1 || classified.MRoots[0] != 3 {
		t.Fatalf("M roots = %v, want [3]", classified.MRoots)
	}
	if classified.Population() != 2 {
		t.Fatalf("population = %d, want 2", classified.Population())
	}
	if !VerifyFollowUp(classified, 0, 0, [][32]byte{m.digest()}) {
		t.Fatal("phase 2 rejected honest follow-up")
	}
}

func TestVerifyDecodeCountIdentityMismatchFails(t *testing.T) {
	l := element(2, 0x20)
	remote := summarize(nil)
	remote.Count = 5
	if _, ok := VerifyDecode(
		BucketRequest{Capacity: 8}, summarize([]testElement{l}), remote,
		[]uint64{2}, lookup([]testElement{l}),
	); ok {
		t.Fatal("count identity mismatch passed phase 1")
	}
}

func TestVerifyDecodeDuplicateRootFails(t *testing.T) {
	l := element(2, 0x20)
	if _, ok := VerifyDecode(
		BucketRequest{Capacity: 8}, summarize([]testElement{l}), summarize(nil),
		[]uint64{2, 2}, lookup([]testElement{l}),
	); ok {
		t.Fatal("duplicate root passed phase 1")
	}
}

func TestVerifyDecodeRootOutsideNodeFails(t *testing.T) {
	l := element(2, 0x20)
	// depth 1, prefix 0 covers only roots with the leading bit clear.
	outside := uint64(1) << 63
	if _, ok := VerifyDecode(
		BucketRequest{Depth: 1, Prefix: 0, Capacity: 8},
		summarize([]testElement{l}), summarize(nil),
		[]uint64{outside}, lookup(nil),
	); ok {
		t.Fatal("out-of-node root passed phase 1")
	}
}

func TestVerifyDecodeEmptyMChecksResidualImmediately(t *testing.T) {
	l := element(7, 0x33)
	classified, ok := VerifyDecode(
		BucketRequest{Capacity: 8}, summarize([]testElement{l}), summarize(nil),
		[]uint64{7}, lookup([]testElement{l}),
	)
	if !ok {
		t.Fatal("local-only difference failed phase 1")
	}
	if len(classified.MRoots) != 0 {
		t.Fatalf("M roots = %v, want empty", classified.MRoots)
	}
}

func TestVerifyDecodeAmbiguousRootSkipsImmediateResidual(t *testing.T) {
	// Two local elements share an H64: the residual cannot be checked until
	// phase 2 resolves the collision. A shared root keeps the count identity
	// consistent (|L| counts roots, not elements).
	first := testElement{h64: 9, q3: 9, h128: [16]byte{1}}
	second := testElement{h64: 9, q3: 9, h128: [16]byte{2}}
	sharedLocal := element(2, 0x44)
	sharedRemote := element(2, 0x88)
	local := []testElement{first, second, sharedLocal}
	remote := []testElement{sharedRemote}
	classified, ok := VerifyDecode(
		BucketRequest{Capacity: 8}, summarize(local), summarize(remote),
		[]uint64{9, 2}, lookup(local),
	)
	if !ok {
		t.Fatal("ambiguous shared-root difference failed phase 1")
	}
	if len(classified.MRoots) != 0 {
		t.Fatalf("M roots = %v, want empty", classified.MRoots)
	}
}

func TestVerifyFollowUpFails(t *testing.T) {
	shared := element(1, 0x10)
	l := element(2, 0x20)
	m := element(3, 0x40)
	local := []testElement{shared, l}
	remote := []testElement{shared, m}
	classified, ok := VerifyDecode(
		BucketRequest{Capacity: 8}, summarize(local), summarize(remote),
		[]uint64{2, 3}, lookup(local),
	)
	if !ok {
		t.Fatal("setup failed")
	}

	if VerifyFollowUp(classified, 1, 0, [][32]byte{m.digest()}) {
		t.Fatal("follow-up for a different node passed")
	}
	if VerifyFollowUp(classified, 0, 0, nil) {
		t.Fatal("follow-up with missing root passed")
	}
	if VerifyFollowUp(classified, 0, 0, [][32]byte{m.digest(), m.digest()}) {
		t.Fatal("follow-up with duplicated root passed")
	}
	tampered := m.digest()
	tampered[16] ^= 0xff
	if VerifyFollowUp(classified, 0, 0, [][32]byte{tampered}) {
		t.Fatal("follow-up with wrong residual passed")
	}
	otherNode := element(4, 0x50)
	if VerifyFollowUp(classified, 0, 0, [][32]byte{otherNode.digest()}) {
		t.Fatal("follow-up with a root outside M passed")
	}
}

func TestBucketContains(t *testing.T) {
	if !bucketContains(0, 0, ^uint64(0)) {
		t.Fatal("depth 0 must cover every root")
	}
	if !bucketContains(1, 0, 1<<62) {
		t.Fatal("leading-zero root should sit under prefix 0")
	}
	if bucketContains(1, 0, 1<<63) {
		t.Fatal("leading-one root must not sit under prefix 0")
	}
	if !bucketContains(32, 0xdeadbeef, uint64(0xdeadbeef)<<32) {
		t.Fatal("depth-32 prefix must match the leading 32 bits")
	}
	if !bucketContains(32, 0xdeadbeef, uint64(0xdeadbeef)<<32|1) {
		t.Fatal("depth-32 membership must ignore trailing bits")
	}
}
