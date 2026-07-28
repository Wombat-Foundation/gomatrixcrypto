package reconcile

import (
	"crypto/sha256"
	"encoding/base64"
	"reflect"
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
	if _, err := MatrixEventDigest32("$not base64", V4Plus); err != ErrInvalidBase64 {
		t.Fatalf("expected ErrInvalidBase64, got %v", err)
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
	if _, err := xorLeft.Subtract(&SyndromeSketch{Coordinates: []uint64{1, 2, 3}}); err != ErrInvalidSketchLength {
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
	if err := rk.Remove(first); err != nil {
		t.Fatal(err)
	}
	if err := rk.Insert(ElementHash{H128: [16]byte{1}, H64: 0}); err != ErrZeroShortIdentifier {
		t.Fatalf("expected ErrZeroShortIdentifier, got %v", err)
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

	sketch, err := c.BuildSketch(1, []ElementHash{event})
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeSyndromeSketch(1, sketch.Encode()); err != nil || !equalSketch(sketch, decoded) {
		t.Fatalf("BuildSketch round-trip failed: %v", err)
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
	if got := c.TransitionBucketBatch(batch, nil, nil, nil, 4096); got.Type != ActionResolveRoots {
		t.Fatalf("expected resolve roots, got %v", got.Type)
	}

	failed := BucketDecodeBatch{FailedBuckets: []FailedBucket{{Depth: 0, Prefix: 0}}}
	next := c.TransitionBucketBatch(failed, []BucketRequest{{Depth: 0, Prefix: 0, Capacity: 64}}, nil, nil, 4096)
	if next.Type != ActionBucketSketches {
		t.Fatalf("expected bucket sketches retry, got %v", next.Type)
	}
	if len(next.Requests) == 0 {
		t.Fatal("expected retry requests")
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
	if _, ok := nextFactorParameter(1), true; !ok {
		t.Fatal("nextFactorParameter sanity")
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

func trimAndCheck(poly *polynomial, want polynomial) bool {
	trim(poly)
	return reflect.DeepEqual(*poly, want)
}
