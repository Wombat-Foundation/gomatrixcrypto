package reconcile

import "testing"

func TestMulBitwiseVectors(t *testing.T) {
	if got := Mul(0x1b, 0x1b); got != 0x145 {
		t.Fatalf("Mul(0x1b,0x1b) = %#x, want %#x", got, 0x145)
	}
	if got := Mul(^uint64(0), ^uint64(0)); got != 0x5555_5555_5555_5513 {
		t.Fatalf("Mul(max,max) = %#x", got)
	}
}

func TestSyndromeSketchRoundTrip(t *testing.T) {
	sketch, err := NewSyndromeSketch(4)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []uint64{1, 2, 3} {
		if err := sketch.Toggle(value); err != nil {
			t.Fatal(err)
		}
	}
	encoded := sketch.Encode()
	decoded, err := DecodeSyndromeSketch(4, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !equalSketch(sketch, decoded) {
		t.Fatalf("decoded sketch mismatch: %#v != %#v", sketch, decoded)
	}
}

func TestRoomAccumulatorEncodeDecode(t *testing.T) {
	var acc RoomAccumulator
	hash := ElementHash{H128: [16]byte{7}}
	if err := acc.Insert(hash); err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeDigest(acc.EncodeDigest())
	if err != nil {
		t.Fatal(err)
	}
	if decoded != acc.Digest {
		t.Fatalf("digest mismatch")
	}
}
