package reconcile

import (
	"crypto/sha256"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func eventIDFromDigest32(digest [32]byte, format EventIDFormat) string {
	switch format {
	case V3:
		return "$" + base64.RawStdEncoding.EncodeToString(digest[:])
	case V4Plus:
		return "$" + base64.RawURLEncoding.EncodeToString(digest[:])
	default:
		panic("unsupported format")
	}
}

func makeOddSyndromes(values []uint64, capacity int) []uint64 {
	odd := make([]uint64, capacity)
	for _, value := range values {
		squared := Mul(value, value)
		power := value
		for i := range odd {
			odd[i] ^= power
			power = Mul(power, squared)
		}
	}
	return odd
}

func strataFromValues(values ...uint64) [StrataCount][StratumCapacity]uint64 {
	var kernel ResidentKernel
	for _, value := range values {
		_ = kernel.Insert(ElementHash{H64: value, H128: [16]byte{byte(value)}})
	}
	return *kernel.Strata()
}

func TestElementHashAndEventIDs(t *testing.T) {
	var digest [32]byte
	for i := range digest {
		digest[i] = byte(i)
	}

	hash := FromDigest32(digest)
	if got, want := hash.H128, ([16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}); got != want {
		t.Fatalf("H128 = %x, want %x", got, want)
	}
	if got, want := hash.H64, uint64(0x0001020304050607); got != want {
		t.Fatalf("H64 = %#x, want %#x", got, want)
	}

	var zeroDigest [32]byte
	if got := FromDigest32(zeroDigest); got.H64 != 1 {
		t.Fatalf("zero digest H64 = %d, want 1", got.H64)
	}

	for _, format := range []EventIDFormat{V3, V4Plus} {
		id := eventIDFromDigest32(digest, format)
		decoded, err := MatrixEventDigest32(id, format)
		if err != nil {
			t.Fatalf("MatrixEventDigest32(%v) failed: %v", format, err)
		}
		if decoded != digest {
			t.Fatalf("decoded digest mismatch for %v", format)
		}
		hash, err := FromMatrixEventID(id, format)
		if err != nil {
			t.Fatalf("FromMatrixEventID(%v) failed: %v", format, err)
		}
		if hash != FromDigest32(digest) {
			t.Fatalf("hash mismatch for %v", format)
		}
		if _, err := DecodeDigest32(id, format); err != nil {
			t.Fatalf("DecodeDigest32(%v) failed: %v", format, err)
		}
	}

	legacyID := "$opaque:example.org"
	legacyDigest := sha256.Sum256([]byte(legacyID))
	got, err := MatrixEventDigest32(legacyID, Legacy)
	if err != nil {
		t.Fatalf("legacy digest failed: %v", err)
	}
	if got != legacyDigest {
		t.Fatalf("legacy digest mismatch")
	}

	if _, err := MatrixEventDigest32("not-an-event-id", V4Plus); err != ErrInvalidEventID {
		t.Fatalf("expected ErrInvalidEventID, got %v", err)
	}
	badFormatID := "$" + base64.RawURLEncoding.EncodeToString(digest[:])
	if _, err := MatrixEventDigest32(badFormatID, EventIDFormat(99)); err != ErrInvalidEventID {
		t.Fatalf("expected ErrInvalidEventID for unsupported format, got %v", err)
	}
	if _, err := MatrixEventDigest32("$not base64", V4Plus); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64, got %v", err)
	}
	if _, err := MatrixEventDigest32("$not base64", V3); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64 for V3, got %v", err)
	}
	if _, err := MatrixEventDigest32("$AA", V3); err != ErrInvalidEventID {
		t.Fatalf("expected ErrInvalidEventID for short V3 digest, got %v", err)
	}
	if _, err := MatrixEventDigest32("$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", V4Plus); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64 for overlong encoded digest, got %v", err)
	}
	if _, ok := trimSigil("$abc"); !ok {
		t.Fatal("trimSigil rejected valid sigil")
	}
	if _, ok := trimSigil("abc"); ok {
		t.Fatal("trimSigil accepted invalid sigil")
	}
}

func TestRoomAccumulatorAndResiduals(t *testing.T) {
	var left, right RoomAccumulator
	first := ElementHash{H128: [16]byte{1}, H64: 11}
	second := ElementHash{H128: [16]byte{2}, H64: 22}

	if err := left.Insert(first); err != nil {
		t.Fatal(err)
	}
	if err := left.Insert(second); err != nil {
		t.Fatal(err)
	}
	if err := right.Insert(first); err != nil {
		t.Fatal(err)
	}

	if left.Count != 2 {
		t.Fatalf("count = %d, want 2", left.Count)
	}
	if err := left.Remove(second); err != nil {
		t.Fatal(err)
	}
	if left.Count != 1 {
		t.Fatalf("count after remove = %d, want 1", left.Count)
	}
	var empty RoomAccumulator
	if err := empty.Remove(second); err != ErrCountUnderflow {
		t.Fatalf("expected underflow, got %v", err)
	}

	left.Count = ^uint64(0)
	if err := left.Insert(first); err != ErrCountOverflow {
		t.Fatalf("expected overflow, got %v", err)
	}

	diff := NewRoomAccumulator()
	if err := diff.Insert(second); err != nil {
		t.Fatal(err)
	}
	expectedResidual := first.H128
	expectedResidual[0] ^= second.H128[0]
	if got := diff.Residual(right); got != expectedResidual {
		t.Fatalf("residual mismatch: %x", got)
	}
	if !VerifyResidual([16]byte{3}, []ElementHash{{H128: [16]byte{1}}, {H128: [16]byte{2}}}) {
		t.Fatal("VerifyResidual returned false")
	}
	if VerifyResidual([16]byte{4}, []ElementHash{{H128: [16]byte{1}}, {H128: [16]byte{2}}}) {
		t.Fatal("VerifyResidual accepted a bad residual")
	}

	etag1 := left.ETag([]string{"$b", "$a"})
	etag2 := left.ETag([]string{"$a", "$b"})
	if etag1 != etag2 {
		t.Fatal("ETag should be order-independent")
	}

	if decoded, err := DecodeDigest(left.EncodeDigest()); err != nil || decoded != left.Digest {
		t.Fatalf("DecodeDigest round-trip failed: %v", err)
	}
	if _, err := DecodeDigest("short"); err != ErrInvalidDigestLength {
		t.Fatalf("expected ErrInvalidDigestLength, got %v", err)
	}
	if _, err := DecodeDigest("!!!!!!!!!!!!!!!!!!!!!!"); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64, got %v", err)
	}
	if _, err := DecodeDigest("AAAAAAAAAAAAAAAAAAAAA"); err != ErrInvalidDigestLength {
		t.Fatalf("expected ErrInvalidDigestLength, got %v", err)
	}
}

func TestSyndromeSketchOperations(t *testing.T) {
	sketch, err := NewSyndromeSketch(4)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewSyndromeSketch(0); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := NewSyndromeSketch(MaxSketchCapacity + 1); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := NewSyndromeSketchFromCoordinates(nil); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}

	coords := []uint64{1, 2, 3, 4}
	fromCoords, err := NewSyndromeSketchFromCoordinates(coords)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromCoords.Coordinates, coords) {
		t.Fatalf("coordinates mismatch: %v", fromCoords.Coordinates)
	}

	if err := sketch.Toggle(1); err != nil {
		t.Fatal(err)
	}
	if err := sketch.Toggle(2); err != nil {
		t.Fatal(err)
	}
	if err := sketch.Toggle(3); err != nil {
		t.Fatal(err)
	}
	if err := sketch.Toggle(0); err != ErrZeroShortIdentifier {
		t.Fatalf("expected ErrZeroShortIdentifier, got %v", err)
	}

	encoded := sketch.Encode()
	decoded, err := DecodeSyndromeSketch(4, encoded)
	if err != nil {
		t.Fatalf("DecodeSyndromeSketch failed: %v", err)
	}
	if !equalSketch(sketch, decoded) {
		t.Fatalf("round-trip mismatch: %#v != %#v", sketch, decoded)
	}
	if _, err := DecodeSyndromeSketch(0, encoded); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := DecodeSyndromeSketch(4, strings.Repeat("!", 43)); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64, got %v", err)
	}
	if _, err := DecodeSyndromeSketch(4, "AAAA"); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength, got %v", err)
	}
	xorLeft, _ := NewSyndromeSketch(4)
	xorRight, _ := NewSyndromeSketch(4)
	_ = xorLeft.Toggle(1)
	_ = xorLeft.Toggle(2)
	_ = xorRight.Toggle(2)
	_ = xorRight.Toggle(3)
	if err := xorLeft.Xor(xorRight); err != nil {
		t.Fatal(err)
	}
	expected, _ := NewSyndromeSketch(4)
	_ = expected.Toggle(1)
	_ = expected.Toggle(3)
	if !equalSketch(xorLeft, expected) {
		t.Fatalf("xor mismatch: %#v != %#v", xorLeft, expected)
	}
	subLeft, _ := NewSyndromeSketch(4)
	subRight, _ := NewSyndromeSketch(4)
	_ = subLeft.Toggle(1)
	_ = subLeft.Toggle(2)
	_ = subRight.Toggle(2)
	subtracted, err := subLeft.Subtract(subRight)
	if err != nil {
		t.Fatal(err)
	}
	expectedSub, _ := NewSyndromeSketch(4)
	_ = expectedSub.Toggle(1)
	if !equalSketch(subtracted, expectedSub) {
		t.Fatalf("subtract mismatch: %#v != %#v", subtracted, expectedSub)
	}
	if _, err := xorLeft.Subtract(&SyndromeSketch{Coordinates: []uint64{1, 2, 3}}); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength, got %v", err)
	}
	if err := xorLeft.Xor(&SyndromeSketch{Coordinates: []uint64{1, 2, 3}}); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength, got %v", err)
	}
	if equalSketch(xorLeft, &SyndromeSketch{Coordinates: []uint64{1, 2, 3, 4}}) {
		t.Fatal("equalSketch should reject capacity mismatch")
	}
	if equalSketch(xorLeft, &SyndromeSketch{Coordinates: []uint64{1, 2, 3}}) {
		t.Fatal("equalSketch should reject different capacities")
	}
	other, _ := NewSyndromeSketch(4)
	if !equalSketch(xorLeft, xorLeft) || equalSketch(xorLeft, other) {
		t.Fatal("equalSketch coverage setup failed")
	}
	mismatch, _ := NewSyndromeSketch(4)
	_ = mismatch.Toggle(4)
	if equalSketch(xorLeft, mismatch) {
		t.Fatal("equalSketch should reject unequal coordinates")
	}
	if got := canonicalStringArray(nil); string(got) != "null" {
		t.Fatalf("expected null canonical encoding, got %q", got)
	}
	if got := canonicalStringArray([]string{"a\nb", "c\\d", "e\"f"}); string(got) != "[\"a\\nb\",\"c\\\\d\",\"e\\\"f\"]" {
		t.Fatalf("unexpected escaped canonical string: %q", got)
	}
	if got := canonicalStringArray([]string{"\b\f\r\t"}); string(got) != "[\"\\b\\f\\r\\t\"]" {
		t.Fatalf("unexpected control-char canonical string: %q", got)
	}
	sortStrings([]string{"b"})
	if _, err := newSketchFromEncodedBytes(1, []byte{0, 0, 0, 0, 0, 0, 0}); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength, got %v", err)
	}

	decodedElements, err := sketch.DecodeElements(4)
	if err != nil {
		t.Fatalf("DecodeElements failed: %v", err)
	}
	if len(decodedElements) == 0 {
		t.Fatal("DecodeElements returned no roots")
	}
	if _, err := sketch.DecodeElements(0); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := sketch.DecodeElements(5); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity for over-capacity decode, got %v", err)
	}
	badDecode, _ := NewSyndromeSketchFromCoordinates([]uint64{1, 2})
	if _, err := badDecode.DecodeElements(1); err != ErrDecodeFailure {
		t.Fatalf("expected ErrDecodeFailure from decode mismatch, got %v", err)
	}
	if containsZero([]uint64{0, 1}) != true || containsZero([]uint64{1, 2}) {
		t.Fatal("containsZero mismatch")
	}
}

func TestResidentKernelAndBucketValidation(t *testing.T) {
	rk := NewResidentKernel()
	first := ElementHash{H128: [16]byte{1}, H64: 8}
	if err := rk.Insert(first); err != nil {
		t.Fatal(err)
	}
	if rk.Accumulator().Count != 1 {
		t.Fatalf("count = %d, want 1", rk.Accumulator().Count)
	}
	if rk.Strata()[3][0] != 8 {
		t.Fatalf("unexpected stratum value: %d", rk.Strata()[3][0])
	}
	if err := rk.Insert(ElementHash{H128: [16]byte{4}, H64: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if err := rk.Remove(ElementHash{H128: [16]byte{4}, H64: 1 << 40}); err != nil {
		t.Fatal(err)
	}
	if err := rk.Remove(first); err != nil {
		t.Fatal(err)
	}
	var emptyRK ResidentKernel
	if err := emptyRK.Remove(first); err != ErrCountUnderflow {
		t.Fatalf("expected ErrCountUnderflow, got %v", err)
	}
	rk.accumulator.Count = ^uint64(0)
	if err := rk.Insert(first); err != ErrCountOverflow {
		t.Fatalf("expected ErrCountOverflow via resident kernel, got %v", err)
	}
	if err := rk.Insert(ElementHash{H128: [16]byte{1}, H64: 0}); err != ErrZeroShortIdentifier {
		t.Fatalf("expected ErrZeroShortIdentifier, got %v", err)
	}
	if err := rk.Remove(ElementHash{H128: [16]byte{1}, H64: 0}); err != ErrZeroShortIdentifier {
		t.Fatalf("expected ErrZeroShortIdentifier on remove, got %v", err)
	}

	if err := ValidateBucketRequests([]BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}}); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if err := ValidateBucketRequests([]BucketRequest{
		{Depth: 0, Prefix: 0, Capacity: 4},
		{Depth: 1, Prefix: 0, Capacity: 4},
	}); err != ErrInvalidBucketIndex {
		t.Fatalf("expected overlap error, got %v", err)
	}
	if err := ValidateBucketRequests([]BucketRequest{{Depth: 33, Prefix: 0, Capacity: 4}}); err != ErrInvalidBucketIndex {
		t.Fatalf("expected invalid depth, got %v", err)
	}
	if err := ValidateBucketRequests([]BucketRequest{{Depth: 31, Prefix: 1 << 31, Capacity: 4}}); err != ErrInvalidBucketIndex {
		t.Fatalf("expected invalid prefix, got %v", err)
	}
	if err := ValidateBucketRequests([]BucketRequest{{Depth: 0, Prefix: 0, Capacity: 0}}); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected invalid capacity, got %v", err)
	}
	overflowRequests := make([]BucketRequest, 0, 129)
	for i := 0; i < 129; i++ {
		overflowRequests = append(overflowRequests, BucketRequest{Depth: 32, Prefix: uint32(i), Capacity: MaxBucketSketchCapacity})
	}
	if err := ValidateBucketRequests(overflowRequests); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected capacity overflow, got %v", err)
	}
}

func TestClientAndTriageFlow(t *testing.T) {
	client, err := NewReconciliationClient(8)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewReconciliationClient(0); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}

	c := *client
	c = c.WithMaxRounds(42)
	if got := c.MaxRounds(); got != 42 {
		t.Fatalf("MaxRounds = %d, want 42", got)
	}
	if threshold, ok := c.GateThreshold(); !ok || threshold != 42*MaxBucketedSketchCapacity {
		t.Fatalf("unexpected gate threshold: %d %v", threshold, ok)
	}
	c = c.WithGateThreshold(nil).AllowUnlimitedDelta()
	if _, ok := c.GateThreshold(); ok {
		t.Fatal("gate threshold should be disabled")
	}

	local := NewResidentKernel()
	remote := RemoteDigest{FrameMatches: false}
	if got := c.SelectAction(&local, remote, 0); got.Type != ActionExtremityDiff {
		t.Fatalf("expected extremity diff, got %v", got.Type)
	}
	if got := c.SelectAction(&local, RemoteDigest{
		Digest:              remote.Digest,
		KnownEventCount:     remote.KnownEventCount,
		FrameMatches:        true,
		HasUnknownExtremity: true,
	}, 0); got.Type != ActionExtremityDiff {
		t.Fatalf("expected unknown extremity fallback, got %v", got.Type)
	}

	event := ElementHash{H128: [16]byte{1}, H64: 1}
	_ = local.Insert(event)
	remote = RemoteDigest{
		Digest:              local.Accumulator().Digest,
		KnownEventCount:     local.Accumulator().Count,
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}
	if got := c.SelectAction(&local, remote, 0); got.Type != ActionSynchronized {
		t.Fatalf("expected synchronized, got %v", got.Type)
	}

	remote.KnownEventCount = 0
	remote.Digest = [16]byte{}
	if got := c.SelectAction(&local, remote, 0); got.Type != ActionBucketSketches {
		t.Fatalf("expected bucket sketches, got %v", got.Type)
	}
	if got := c.SelectAction(&local, RemoteDigest{
		Digest:              [16]byte{7},
		KnownEventCount:     local.Accumulator().Count,
		Strata:              strataFromValues(1, 2, 4, 8, 3, 5),
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}, 0); got.Type != ActionBucketSketches {
		t.Fatalf("expected estimate-driven bucket sketches, got %v", got)
	}
	overflowLocal := NewResidentKernel()
	if err := overflowLocal.Insert(ElementHash{H128: [16]byte{3}, H64: 3}); err != nil {
		t.Fatal(err)
	}
	if got := c.SelectAction(&overflowLocal, RemoteDigest{
		Digest:              [16]byte{9},
		KnownEventCount:     0,
		Strata:              *overflowLocal.Strata(),
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}, maxInt); got.Type != ActionBucketSketches || len(got.Requests) != 64 {
		t.Fatalf("expected overflow-localized bucket sketches, got %v", got)
	}

	wide := NewResidentKernel()
	wideAction := c.SelectAction(&wide, RemoteDigest{
		Digest:              [16]byte{2},
		KnownEventCount:     1000,
		Strata:              *wide.Strata(),
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}, 0)
	if wideAction.Type != ActionBucketSketches || len(wideAction.Requests) != 64 {
		t.Fatalf("expected 64-way localization, got %#v", wideAction)
	}
	if wideAction.Requests[0].Depth != 6 || wideAction.Requests[0].Prefix != 0 || wideAction.Requests[0].Capacity != 24 {
		t.Fatalf("unexpected localized request: %#v", wideAction.Requests[0])
	}
	if wideAction.Requests[63].Prefix != 63 {
		t.Fatalf("unexpected final localized prefix: %#v", wideAction.Requests[63])
	}

	hugeAction := c.SelectAction(&wide, RemoteDigest{
		Digest:              [16]byte{3},
		KnownEventCount:     1000000,
		Strata:              *wide.Strata(),
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}, 0)
	if hugeAction.Type != ActionBucketSketches || len(hugeAction.Requests) != 64 {
		t.Fatalf("expected clamped localization, got %#v", hugeAction)
	}
	if hugeAction.Requests[0].Capacity != MaxBucketSketchCapacity {
		t.Fatalf("expected clamped bucket capacity, got %#v", hugeAction.Requests[0])
	}

	gated := c.WithGateThreshold(func() *uint64 {
		threshold := uint64(1)
		return &threshold
	}())
	if got := gated.SelectAction(&wide, RemoteDigest{
		Digest:              [16]byte{2},
		KnownEventCount:     1000,
		Strata:              *wide.Strata(),
		FrameMatches:        true,
		HasUnknownExtremity: false,
	}, 0); got.Type != ActionExtremityDiff {
		t.Fatalf("expected gate fallback, got %#v", got)
	}

	sketch, err := c.BuildSketch(1, []ElementHash{event})
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeSyndromeSketch(1, sketch.Encode()); err != nil || !equalSketch(sketch, decoded) {
		t.Fatalf("BuildSketch round-trip failed: %v", err)
	}
	if _, err := c.BuildSketch(0, nil); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := c.BuildSketch(c.maxSketchCapacity+1, nil); err != ErrInvalidSketchCapacity {
		t.Fatalf("expected ErrInvalidSketchCapacity, got %v", err)
	}
	if _, err := c.BuildSketch(1, []ElementHash{{H128: [16]byte{1}, H64: 0}}); err != ErrZeroShortIdentifier {
		t.Fatalf("expected ErrZeroShortIdentifier, got %v", err)
	}
	if got := provisionCapacity(uint64(maxInt), 0); got != -1 {
		t.Fatalf("expected provisionCapacity overflow sentinel, got %d", got)
	}
	if got := provisionCapacity(5, 3); got != 15 {
		t.Fatalf("expected headroom contribution, got %d", got)
	}
	if got := ceilDiv(0, 3); got != 0 {
		t.Fatalf("ceilDiv zero numerator = %d", got)
	}
	if got := ceilDiv(1, 0); got != 0 {
		t.Fatalf("ceilDiv zero denominator = %d", got)
	}
	if got, ok := provisionBucketCapacity(1, 10); !ok || got != 10 {
		t.Fatalf("provisionBucketCapacity floor branch mismatch: %d %v", got, ok)
	}
	if got, ok := provisionBucketCapacity(uint64(maxInt)+1, 4); ok || got != 0 {
		t.Fatalf("provisionBucketCapacity overflow branch mismatch: %d %v", got, ok)
	}
	if got, ok := provisionBucketCapacity(64, 4); !ok || got != MaxBucketSketchCapacity {
		t.Fatalf("provisionBucketCapacity cap branch mismatch: %d %v", got, ok)
	}
	if got, err := decodePinSketch(makeOddSyndromes(nil, 2), 2); err != nil || len(got) != 0 {
		t.Fatalf("decodePinSketch empty locator mismatch: %v %v", got, err)
	}
	if !VerifyGlobalResidual([16]byte{3}, [][16]byte{{1}}, [][16]byte{{2}}) {
		t.Fatal("VerifyGlobalResidual failed on split slices")
	}

	if !VerifyGlobalResidual([16]byte{3}, [][16]byte{{1}, {2}}, nil) {
		t.Fatal("VerifyGlobalResidual failed")
	}
	if VerifyGlobalResidual([16]byte{4}, [][16]byte{{1}, {2}}, nil) {
		t.Fatal("VerifyGlobalResidual accepted bad data")
	}

	batch := BucketDecodeBatch{
		SuccessfulBuckets: []BucketDecodeSuccess{{Depth: 1, Prefix: 0, Roots: []uint64{10}}},
	}
	if got := c.TransitionBucketBatch(batch, nil, nil, nil, 0, 4096); got.Type != ActionResolveRoots {
		t.Fatalf("expected resolve roots, got %v", got.Type)
	}

	failed := BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 0, Prefix: 0}}}
	next := c.TransitionBucketBatch(failed, []BucketRequest{{Depth: 0, Prefix: 0, Capacity: MaxBucketSketchCapacity}}, nil, nil, 0, 4096)
	if next.Type != ActionBucketSketches {
		t.Fatalf("expected bucket sketches retry, got %v", next.Type)
	}
	if got := c.TransitionBucketBatch(failed, []BucketRequest{{Depth: 0, Prefix: 0, Capacity: MaxBucketSketchCapacity}}, nil, nil, c.MaxRounds(), 4096); got.Type != ActionExtremityDiff {
		t.Fatalf("expected round-limit fallback, got %v", got.Type)
	}
	if len(next.Requests) == 0 {
		t.Fatal("expected retry requests")
	}
	if next.Requests[0].Capacity != 10 || next.Requests[0].Depth != 1 || next.Requests[0].Prefix != 0 {
		t.Fatalf("unexpected split retry request: %#v", next.Requests[0])
	}

	if got := absDiffU64(10, 3); got != 7 {
		t.Fatalf("absDiffU64 = %d, want 7", got)
	}
	if got := ceilDiv(10, 3); got != 4 {
		t.Fatalf("ceilDiv = %d, want 4", got)
	}
	if got := maxU64(10, 3); got != 10 {
		t.Fatalf("maxU64 = %d, want 10", got)
	}
	if got, ok := provisionBucketCapacity(4, 4); !ok || got < 4 {
		t.Fatalf("provisionBucketCapacity unexpected result: %d %v", got, ok)
	}
	if got := provisionCapacity(5, 0); got <= 0 {
		t.Fatalf("provisionCapacity = %d, want positive", got)
	}
}

func TestPinSketchHelpersAndDecoding(t *testing.T) {
	if _, ok := gf64Inv(0); ok {
		t.Fatal("gf64Inv should reject zero")
	}
	inv, ok := gf64Inv(3)
	if !ok || Mul(3, inv) != 1 {
		t.Fatal("gf64Inv failed round trip")
	}

	if got, ok := factorTrialCost(0); !ok || got != 0 {
		t.Fatalf("factorTrialCost(0) = %d, %v", got, ok)
	}
	if got := nextFactorParameter(1); got == 0 {
		t.Fatal("nextFactorParameter returned zero")
	}

	values := []uint64{1, 2, 3, 4}
	odd := makeOddSyndromes(values, len(values))
	decoded, err := decodePinSketch(odd, len(values))
	if err != nil {
		t.Fatalf("decodePinSketch failed: %v", err)
	}
	if !reflect.DeepEqual(decoded, values) {
		t.Fatalf("decoded roots = %v, want %v", decoded, values)
	}

	if got, ok := solveQuadraticForm(Mul(5, 5) ^ 5); !ok || Mul(got, got)^got != (Mul(5, 5)^5) {
		t.Fatal("solveQuadraticForm failed")
	}

	var roots []uint64
	if err := findRoots(polynomial{Mul(1, 2), 1 ^ 2, 1}, &roots); err != nil {
		t.Fatalf("findRoots failed: %v", err)
	}
	if len(roots) == 0 {
		t.Fatal("findRoots returned no roots")
	}

	if !polySquare(&polynomial{}) {
		t.Fatal("polySquare empty should succeed")
	}

	poly := polynomial{1, 2, 3}
	if !trimAndCheck(&poly, polynomial{1, 2, 3}) {
		t.Fatal("trim helper sanity")
	}
}

func TestDecodeBucketSketchesAndHelpers(t *testing.T) {
	success, err := NewSyndromeSketch(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := success.Toggle(7); err != nil {
		t.Fatal(err)
	}
	successBytes := make([]byte, 0, 16)
	for _, coord := range success.Coordinates {
		successBytes = append(successBytes,
			byte(coord),
			byte(coord>>8),
			byte(coord>>16),
			byte(coord>>24),
			byte(coord>>32),
			byte(coord>>40),
			byte(coord>>48),
			byte(coord>>56),
		)
	}

	failure, err := NewSyndromeSketch(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []uint64{1, 2, 3} {
		if err := failure.Toggle(value); err != nil {
			t.Fatal(err)
		}
	}
	failureBytes := make([]byte, 0, 16)
	for _, coord := range failure.Coordinates {
		failureBytes = append(failureBytes,
			byte(coord),
			byte(coord>>8),
			byte(coord>>16),
			byte(coord>>24),
			byte(coord>>32),
			byte(coord>>40),
			byte(coord>>48),
			byte(coord>>56),
		)
	}

	encoded := append(successBytes, failureBytes...)
	requests := []BucketRequest{
		{Depth: 8, Prefix: 1, Capacity: 2},
		{Depth: 8, Prefix: 9, Capacity: 2},
	}
	batch, err := DecodeBucketSketches(encoded, requests)
	if err != nil {
		t.Fatalf("DecodeBucketSketches failed: %v", err)
	}
	if len(batch.SuccessfulBuckets) != 1 || len(batch.FailedBuckets) != 1 {
		t.Fatalf("unexpected batch result: %#v", batch)
	}
	if batch.SuccessfulBuckets[0].Depth != 8 || batch.SuccessfulBuckets[0].Prefix != 1 {
		t.Fatalf("unexpected success bucket: %#v", batch.SuccessfulBuckets[0])
	}
	if !reflect.DeepEqual(batch.SuccessfulBuckets[0].Roots, []uint64{7}) {
		t.Fatalf("unexpected success roots: %v", batch.SuccessfulBuckets[0].Roots)
	}
	if batch.FailedBuckets[0] != (FailedBucket{Depth: 8, Prefix: 9}) {
		t.Fatalf("unexpected failed bucket: %#v", batch.FailedBuckets[0])
	}

	if _, err := DecodeBucketSketches(encoded[:len(encoded)-1], requests); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength, got %v", err)
	}
	leftover := append(append([]byte(nil), encoded...), 0)
	if _, err := DecodeBucketSketches(leftover, requests); err != ErrInvalidSketchLength {
		t.Fatalf("expected ErrInvalidSketchLength for leftover bytes, got %v", err)
	}
	if _, err := DecodeBucketSketches(encoded, []BucketRequest{{Depth: 0, Prefix: 0, Capacity: 4}, {Depth: 1, Prefix: 0, Capacity: 4}}); err != ErrInvalidBucketIndex {
		t.Fatalf("expected ErrInvalidBucketIndex, got %v", err)
	}

	if got, ok := safeMul(0, maxInt); !ok || got != 0 {
		t.Fatalf("safeMul zero path failed: %d %v", got, ok)
	}
	if _, ok := safeMul(maxInt, 2); ok {
		t.Fatal("safeMul should overflow")
	}
	if got, ok := safeAdd(1, 2); !ok || got != 3 {
		t.Fatalf("safeAdd = %d %v, want 3 true", got, ok)
	}
	if _, ok := safeAdd(maxInt, 1); ok {
		t.Fatal("safeAdd should overflow")
	}
}

func TestMatrixAndPinSketchHelperBranches(t *testing.T) {
	if _, err := FromMatrixEventID("not-an-event-id", V4Plus); err != ErrInvalidEventID {
		t.Fatalf("expected ErrInvalidEventID, got %v", err)
	}

	var emptyPoly polynomial
	if makeMonic(&emptyPoly) {
		t.Fatal("makeMonic should reject empty polynomials")
	}
	poly := polynomial{1, 2, 3}
	if !makeMonic(&poly) {
		t.Fatal("makeMonic should accept a monic polynomial")
	}
	if !polyMod([]uint64{1, 2, 1}, &poly) {
		t.Fatal("polyMod should accept monic modulus")
	}
	value := polynomial{1, 2}
	if polyMod([]uint64{1, 2}, &value) {
		t.Fatal("polyMod should reject non-monic modulus")
	}

	if _, ok := polyDiv(polynomial{1}, []uint64{1, 1}); ok {
		t.Fatal("polyDiv should reject short dividend")
	}
	if got, ok := polyDiv(polynomial{2, 3, 1}, []uint64{1, 1}); !ok || !reflect.DeepEqual(got, polynomial{2, 1}) {
		t.Fatalf("polyDiv success mismatch: %v %v", got, ok)
	}
	if got, ok := polyDiv(polynomial{0, 1, 1}, []uint64{1, 1}); !ok || !reflect.DeepEqual(got, polynomial{0, 1}) {
		t.Fatalf("polyDiv zero-term mismatch: %v %v", got, ok)
	}

	if got, ok := polyGCD(polynomial{1, 1}, polynomial{1, 0, 1}); !ok || !reflect.DeepEqual(got, polynomial{1, 1}) {
		t.Fatalf("polyGCD mismatch: %v %v", got, ok)
	}

	if _, ok := traceMod([]uint64{1, 1}, 1); !ok {
		t.Fatal("traceMod should succeed")
	}
	if _, ok := traceMod([]uint64{1, 0}, 1); ok {
		t.Fatal("traceMod should reject non-monic modulus")
	}
	if got, ok := polyGCD(polynomial{1, 1}, polynomial{0}); ok || got != nil {
		t.Fatalf("polyGCD should fail on zero divisor, got %v %v", got, ok)
	}
	if got, ok := polyGCD(polynomial{1}, polynomial{1, 0, 1}); !ok || !reflect.DeepEqual(got, polynomial{1}) {
		t.Fatalf("polyGCD should normalize the gcd, got %v %v", got, ok)
	}
	if got, ok := polyGCD(nil, nil); ok || got != nil {
		t.Fatalf("polyGCD should reject empty inputs, got %v %v", got, ok)
	}
	var failedRoots []uint64
	failedWork := maxFactorWork
	if err := findRootsWithBudget(polynomial{1, 2, 3, 4}, &failedRoots, &failedWork); err != ErrDecodeFailure {
		t.Fatalf("expected ErrDecodeFailure from non-monic factorization, got %v", err)
	}
	zeroRoots := []uint64{}
	if err := findRoots(polynomial{0, 1, 1}, &zeroRoots); err != nil {
		t.Fatalf("findRoots zero-root quadratic failed: %v", err)
	}
	if !reflect.DeepEqual(zeroRoots, []uint64{0, 1}) {
		t.Fatalf("zero-root quadratic mismatch: %v", zeroRoots)
	}
	if err := findRoots(polynomial{1, 0, 1}, &zeroRoots); err != ErrDecodeFailure {
		t.Fatalf("expected ErrDecodeFailure for inseparable quadratic, got %v", err)
	}
	var inconsistentTarget uint64
	for bit := 0; bit < 64; bit++ {
		target := uint64(1) << uint(bit)
		trace := target
		power := target
		for i := 1; i < 64; i++ {
			power = Mul(power, power)
			trace ^= power
		}
		if trace == 1 {
			inconsistentTarget = target
			break
		}
	}
	if inconsistentTarget == 0 {
		t.Fatal("failed to find inconsistent quadratic target")
	}
	if got, ok := solveQuadraticForm(inconsistentTarget); ok || got != 0 {
		t.Fatalf("solveQuadraticForm should reject inconsistent target, got %d %v", got, ok)
	}
	var emptyRoots []uint64
	emptyWork := maxFactorWork
	if err := findRootsWithBudget(nil, &emptyRoots, &emptyWork); err != ErrDecodeFailure {
		t.Fatalf("expected ErrDecodeFailure for empty polynomial, got %v", err)
	}
	constantRoots := []uint64{}
	constantWork := maxFactorWork
	if err := findRootsWithBudget(polynomial{1}, &constantRoots, &constantWork); err != nil || len(constantRoots) != 0 {
		t.Fatalf("expected constant polynomial to decode trivially, got %v %v", constantRoots, err)
	}
	quadraticFailure := []uint64{}
	quadraticWork := maxFactorWork
	if err := findRootsWithBudget(polynomial{inconsistentTarget, 1, 1}, &quadraticFailure, &quadraticWork); err != ErrDecodeFailure {
		t.Fatalf("expected quadratic decode failure, got %v", err)
	}

	var roots []uint64
	work := 0
	pairProducts := Mul(1, 2) ^ Mul(1, 3) ^ Mul(2, 3)
	polynomialWithThreeRoots := polynomial{Mul(Mul(1, 2), 3), pairProducts, 0, 1}
	if err := findRootsWithBudget(polynomialWithThreeRoots, &roots, &work); err != ErrBudgetExhausted {
		t.Fatalf("expected budget exhaustion, got %v", err)
	}
	if len(roots) != 0 {
		t.Fatalf("expected no roots after budget exhaustion, got %v", roots)
	}

	if cost, ok := factorTrialCost(1000); !ok || cost <= maxFactorWork {
		t.Fatalf("unexpected factorTrialCost(1000) = %d %v", cost, ok)
	}
	if cost, ok := factorTrialCost(-1); ok || cost != 0 {
		t.Fatalf("factorTrialCost(-1) = %d %v", cost, ok)
	}
	if cost, ok := factorTrialCost(4_000_000_000); ok || cost != 0 {
		t.Fatalf("factorTrialCost overflow = %d %v", cost, ok)
	}
	if cost, ok := factorTrialCost(400_000_000); ok || cost != 0 {
		t.Fatalf("factorTrialCost trace overflow = %d %v", cost, ok)
	}
	if trailingZeros64(0) != 64 {
		t.Fatal("trailingZeros64(0) should be 64")
	}
}

func TestEstimateDeltaRustCases(t *testing.T) {
	local := strataFromValues()
	remote := local
	if got, ok, err := EstimateDelta(&local, &remote); err != nil || !ok || got != 0 {
		t.Fatalf("EstimateDelta identical = %d %v %v", got, ok, err)
	}
	var empty [StrataCount][StratumCapacity]uint64
	if got, ok, err := EstimateDelta(&local, &empty); err != nil || !ok || got != 0 {
		t.Fatalf("EstimateDelta empty remote = %d %v %v", got, ok, err)
	}

	remote = strataFromValues(1, 2, 4, 8, 3, 5)
	if got, ok, err := EstimateDelta(&local, &remote); err != nil || !ok || got != 6 {
		t.Fatalf("EstimateDelta sparse tail = %d %v %v", got, ok, err)
	}

	remote = strataFromValues(1, 3, 5, 7, 9, 11, 13, 15, 17)
	if got, ok, err := EstimateDelta(&local, &remote); err != nil || ok || got != 0 {
		t.Fatalf("EstimateDelta sparse failure = %d %v %v", got, ok, err)
	}

	var undecodableLocal, undecodableRemote [StrataCount][StratumCapacity]uint64
	foundUndecodable := false
	seed := uint64(0x9e3779b97f4a7c15)
	for attempt := 0; attempt < 256; attempt++ {
		seed ^= seed << 7
		seed ^= seed >> 9
		seed ^= seed << 8
		for i := 0; i < StratumCapacity; i++ {
			seed = nextFactorParameter(seed)
			undecodableRemote[StrataCount-1][i] = seed
		}
		if got, ok, err := EstimateDelta(&undecodableLocal, &undecodableRemote); err == nil && !ok && got == 0 {
			foundUndecodable = true
			break
		}
	}
	if !foundUndecodable {
		t.Fatal("failed to provoke undecodable EstimateDelta fallback")
	}
}

func TestClientTransitionAndDecodeFailures(t *testing.T) {
	client, err := NewReconciliationClient(8)
	if err != nil {
		t.Fatal(err)
	}

	// Retry a failed bucket at a larger capacity.
	retry := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: 8}},
		[]uint64{1, 2},
		nil,
		0,
		4096,
	)
	if retry.Type != ActionBucketSketches || len(retry.Requests) != 1 {
		t.Fatalf("unexpected retry action: %#v", retry)
	}
	if retry.Requests[0].Depth != 4 || retry.Requests[0].Prefix != 3 || retry.Requests[0].Capacity <= 8 {
		t.Fatalf("unexpected retry request: %#v", retry.Requests[0])
	}

	// Split a max-capacity bucket into two narrower buckets.
	split := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 0, Prefix: 0}}},
		[]BucketRequest{{Depth: 0, Prefix: 0, Capacity: MaxBucketSketchCapacity}},
		nil,
		nil,
		0,
		4096,
	)
	if split.Type != ActionBucketSketches || len(split.Requests) != 2 {
		t.Fatalf("unexpected split action: %#v", split)
	}
	if split.Requests[0].Depth != 1 || split.Requests[1].Depth != 1 {
		t.Fatalf("unexpected split depths: %#v", split.Requests)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 31, Prefix: 1}}},
		[]BucketRequest{{Depth: 31, Prefix: 1, Capacity: MaxBucketSketchCapacity}},
		nil,
		nil,
		0,
		4096,
	); got.Type != ActionExtremityDiff {
		t.Fatalf("expected extremity diff for max-depth bucket, got %#v", got)
	}

	// Missing prior request falls back to extremity diff.
	missing := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 2, Prefix: 1}}},
		[]BucketRequest{{Depth: 2, Prefix: 0, Capacity: 8}},
		nil,
		nil,
		0,
		4096,
	)
	if missing.Type != ActionExtremityDiff {
		t.Fatalf("expected extremity diff, got %#v", missing)
	}

	// Aggregate cap enforcement falls back as well.
	overflow := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}, {Depth: 4, Prefix: 4}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: 8}, {Depth: 4, Prefix: 4, Capacity: 8}},
		nil,
		nil,
		0,
		8,
	)
	if overflow.Type != ActionExtremityDiff {
		t.Fatalf("expected extremity diff on aggregate overflow, got %#v", overflow)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: 8}},
		[]uint64{1, 2, 3},
		func() *uint64 {
			v := uint64(10)
			return &v
		}(),
		0,
		4096,
	); got.Type != ActionBucketSketches {
		t.Fatalf("expected estimate-aware retry, got %#v", got)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: 8}},
		nil,
		func() *uint64 {
			v := ^uint64(0)
			return &v
		}(),
		0,
		5000,
	); got.Type != ActionExtremityDiff {
		t.Fatalf("expected overflow fallback from huge estimate, got %#v", got)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: MaxBucketSketchCapacity}},
		nil,
		func() *uint64 {
			v := ^uint64(0)
			return &v
		}(),
		0,
		4096,
	); got.Type != ActionExtremityDiff {
		t.Fatalf("expected split overflow fallback, got %#v", got)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 4, Prefix: 3}}},
		[]BucketRequest{{Depth: 4, Prefix: 3, Capacity: MaxBucketSketchCapacity}},
		nil,
		func() *uint64 {
			v := uint64(2)
			return &v
		}(),
		0,
		4,
	); got.Type != ActionExtremityDiff {
		t.Fatalf("expected aggregate-cap split overflow, got %#v", got)
	}
	if got := client.TransitionBucketBatch(
		BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 1, Prefix: 0}}},
		nil,
		nil,
		nil,
		0,
		4096,
	); got.Type != ActionExtremityDiff {
		t.Fatalf("expected extremity diff with missing request set, got %#v", got)
	}

	// Corrupt a valid sketch so DecodeElements reaches the validation failure path.
	sketch, err := NewSyndromeSketch(2)
	if err != nil {
		t.Fatal(err)
	}
	if err := sketch.Toggle(1); err != nil {
		t.Fatal(err)
	}
	sketch.Coordinates[0] ^= 1
	if _, err := sketch.DecodeElements(2); err != ErrDecodeFailure {
		t.Fatalf("expected ErrDecodeFailure, got %v", err)
	}

	// ETag escaping path.
	etag := NewRoomAccumulator().ETag([]string{"$quoted\nline", "$back\\slash"})
	if etag == "" {
		t.Fatal("ETag should not be empty")
	}
}

func trimAndCheck(poly *polynomial, want polynomial) bool {
	trim(poly)
	return reflect.DeepEqual(*poly, want)
}
