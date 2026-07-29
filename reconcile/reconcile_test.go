package reconcile

import "testing"

func TestMulBitwiseVectors(t *testing.T) {
	vectors := []struct {
		left  uint64
		right uint64
		want  uint64
	}{
		{0x0000_0000_0000_0000, 0xffff_ffff_ffff_ffff, 0x0000_0000_0000_0000},
		{0x0000_0000_0000_0001, 0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff},
		{0x0000_0000_0000_001b, 0x0000_0000_0000_001b, 0x0000_0000_0000_0145},
		{0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_ffff, 0x5555_5555_5555_5513},
		{0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0xc000_0000_0000_005a},
	}
	for _, vector := range vectors {
		if got := Mul(vector.left, vector.right); got != vector.want {
			t.Fatalf("Mul(%#x,%#x) = %#x, want %#x", vector.left, vector.right, got, vector.want)
		}
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
