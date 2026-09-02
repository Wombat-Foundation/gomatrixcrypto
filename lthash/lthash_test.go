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
	const want = "2lrdUeI2X8_GVxDIJBk-43OKIkuea0oTar62Xs5niaM"
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
		173, 143, 238, 133, 116, 45, 142, 118, 230, 225, 87, 181, 99, 179, 124, 211,
		229, 250, 118, 139, 173, 24, 157, 114, 159, 169, 20, 226, 222, 151, 119, 187,
	}; got != want {
		t.Fatalf("one-entry overlay digest mismatch: got %v want %v", got, want)
	}

	var two RedactionOverlay
	two.Insert("m.room.create", "", "$create")
	two.Insert("m.room.member", "@alice:example.org", "$state")
	if got, want := two.Digest(), [ChecksumLen]byte{
		147, 118, 49, 59, 191, 183, 6, 103, 233, 36, 241, 248, 184, 93, 173, 224,
		42, 114, 189, 236, 2, 122, 198, 19, 125, 159, 242, 122, 65, 4, 145, 97,
	}; got != want {
		t.Fatalf("two-entry overlay digest mismatch: got %v want %v", got, want)
	}

	var custom RedactionOverlay
	custom.Insert("org.example.custom", "key", "$custom")
	if got, want := custom.Digest(), [ChecksumLen]byte{
		177, 21, 204, 101, 0, 30, 236, 16, 131, 10, 130, 158, 76, 21, 74, 94,
		123, 206, 66, 97, 110, 243, 218, 53, 119, 208, 66, 214, 19, 58, 156, 66,
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
