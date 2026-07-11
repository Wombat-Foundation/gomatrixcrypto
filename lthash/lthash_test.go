package lthash

import (
	"slices"
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
	const want = "038b52c62ec404f966822f864bb4db91d2f81ef262aed88c6610550c5b904d54"
	if got != want {
		t.Fatalf("checksum mismatch: got %s want %s", got, want)
	}
}
