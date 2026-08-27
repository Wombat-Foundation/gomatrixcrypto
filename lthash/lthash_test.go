package lthash

import (
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestInsertRemoveRoundTrip(t *testing.T) {
	var h Hash
	h.Insert("m.room.create", "", "$a:example.org")
	h.Insert("m.room.member", "@alice:example.org", "$b:example.org")
	h.Remove("m.room.member", "@alice:example.org", "$b:example.org")
	h.Remove("m.room.create", "", "$a:example.org")
	if h != (Hash{}) {
		t.Fatalf("expected zero hash after round-trip")
	}
}

func TestReplaceMatchesRemovePlusInsert(t *testing.T) {
	var direct Hash
	direct.Insert("m.room.name", "", "$old")
	direct.Replace("m.room.name", "", "$old", "$new")

	var stepwise Hash
	stepwise.Insert("m.room.name", "", "$old")
	stepwise.Remove("m.room.name", "", "$old")
	stepwise.Insert("m.room.name", "", "$new")

	if direct != stepwise {
		t.Fatalf("replace did not match remove+insert")
	}
}

func TestOrderIndependent(t *testing.T) {
	entries := []Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
		{EventType: "m.room.member", StateKey: "@bob:example.org", EventID: "$c"},
	}

	h1 := FromEntries(entries)
	slices.Reverse(entries)
	h2 := FromEntries(entries)

	if h1 != h2 {
		t.Fatalf("expected order-independent hash")
	}
}

func TestChecksumStable(t *testing.T) {
	h := FromEntries([]Entry{
		{EventType: "m.room.create", EventID: "$a"},
		{EventType: "m.room.member", StateKey: "@alice:example.org", EventID: "$b"},
	})

	got := h.String()
	const want = "6KCo8KybJLXxhBCClkubGjZCmRB5RXsLGUFusKFc8oA"
	if got != want {
		t.Fatalf("checksum mismatch: got %s want %s", got, want)
	}
}

func TestTruncateToU16LimitPreservesUTF8Boundaries(t *testing.T) {
	input := strings.Repeat("a", 65534) + "é"
	got, n := truncateToU16Limit(input)
	if n != 65534 {
		t.Fatalf("unexpected truncated length: got %d", n)
	}
	if len(got) != 65534 {
		t.Fatalf("unexpected byte length after truncate: got %d", len(got))
	}
	if !strings.HasSuffix(got, "a") {
		t.Fatalf("truncate cut to the wrong boundary")
	}
}

func TestSeedPanicsOnReadFailure(t *testing.T) {
	oldReadFull := readFull
	readFull = func(io.Reader, []byte) (int, error) {
		return 0, errors.New("boom")
	}
	t.Cleanup(func() { readFull = oldReadFull })

	defer func() {
		if recover() == nil {
			t.Fatalf("expected seed to panic on read failure")
		}
	}()

	_ = seed("m.room.create", "", "$a:example.org")
}

func TestRedactionOverlayVectors(t *testing.T) {
	var one RedactionOverlay
	one.Insert("m.room.member", "@alice:example.org", "$state")
	if got, want := one.Digest(), [ChecksumLen]byte{
		69, 243, 113, 245, 224, 85, 213, 42, 145, 18, 212, 145, 211, 128, 87, 65,
		242, 201, 250, 196, 142, 78, 66, 51, 101, 158, 98, 105, 6, 218, 254, 190,
	}; got != want {
		t.Fatalf("one-entry overlay digest mismatch: got %v want %v", got, want)
	}

	var two RedactionOverlay
	two.Insert("m.room.create", "", "$create")
	two.Insert("m.room.member", "@alice:example.org", "$state")
	if got, want := two.Digest(), [ChecksumLen]byte{
		54, 140, 209, 168, 4, 44, 140, 28, 220, 20, 48, 207, 210, 180, 227, 77,
		28, 8, 19, 140, 157, 131, 50, 182, 108, 137, 17, 37, 212, 109, 40, 231,
	}; got != want {
		t.Fatalf("two-entry overlay digest mismatch: got %v want %v", got, want)
	}

	var custom RedactionOverlay
	custom.Insert("org.example.custom", "key", "$custom")
	if got, want := custom.Digest(), [ChecksumLen]byte{
		170, 247, 17, 119, 141, 227, 146, 115, 229, 232, 55, 1, 194, 64, 252, 131,
		61, 17, 11, 81, 6, 9, 121, 44, 58, 85, 193, 228, 45, 47, 192, 70,
	}; got != want {
		t.Fatalf("custom overlay digest mismatch: got %v want %v", got, want)
	}
}

func TestRedactionOverlayOrderIndependentAndReversible(t *testing.T) {
	var left, reordered RedactionOverlay
	left.Insert("m.room.member", "@alice:example.org", "$state")
	reordered.Insert("m.room.member", "@bob:example.org", "$other-state")
	reordered.Insert("m.room.member", "@alice:example.org", "$state")

	var expected RedactionOverlay
	expected.Insert("m.room.member", "@alice:example.org", "$state")
	expected.Insert("m.room.member", "@bob:example.org", "$other-state")
	if reordered != expected {
		t.Fatalf("overlay accumulation depends on insertion order")
	}

	reordered.Remove("m.room.member", "@bob:example.org", "$other-state")
	if reordered != left {
		t.Fatalf("overlay removal did not reverse insertion")
	}
}
