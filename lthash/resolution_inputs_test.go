package lthash

import (
	"bytes"
	"testing"
)

func TestResolutionInputEncodingCanonical(t *testing.T) {
	a := ResolutionInputRecord{EventID: "$e", EventType: "m.room.member", StateKey: "@a:x", AuthEvents: []string{"$b", "$a"}}
	b := a
	b.AuthEvents = []string{"$a", "$b"}
	if !bytes.Equal(a.Encode(), b.Encode()) {
		t.Fatal("edge order must not affect encoding")
	}

	want := []byte{2, 0, '$', 'e', 13, 0}
	want = append(want, "m.room.member"...)
	want = append(want, 4, 0)
	want = append(want, "@a:x"...)
	want = append(want, 2, 0, 0, 0, 2, 0, '$', 'a', 2, 0, '$', 'b', 0, 0, 0, 0)
	if !bytes.Equal(a.Encode(), want) {
		t.Fatalf("encoding mismatch:\n got %v\nwant %v", a.Encode(), want)
	}
}

func TestResolutionInputsDistinguishEdgesAndDomain(t *testing.T) {
	base := ResolutionInputRecord{EventID: "$e", EventType: "m.room.name", AuthEvents: []string{"$c"}}
	rewired := base
	rewired.AuthEvents = []string{"$d"}

	var x, y ResolutionInputs
	x.Insert(base)
	y.Insert(rewired)
	if x.Digest() == y.Digest() {
		t.Fatal("different edges must be distinct elements")
	}
	x.Remove(base)
	if x != (ResolutionInputs{}) {
		t.Fatal("insert/remove must round-trip to empty")
	}

	var overlay RedactionOverlay
	overlay.Insert("m.room.name", "", "$e")
	var inputs ResolutionInputs
	inputs.Insert(ResolutionInputRecord{EventID: "$e", EventType: "m.room.name"})
	if overlay.Digest() == inputs.Digest() {
		t.Fatal("domains must be separated")
	}
}

// Cross-implementation vector; the same value is pinned in rezzy.
func TestResolutionInputsVector(t *testing.T) {
	var x ResolutionInputs
	x.Insert(ResolutionInputRecord{EventID: "$e", EventType: "m.room.member", StateKey: "@a:x", AuthEvents: []string{"$b", "$a"}, StatePredecessors: []string{"$p"}})
	x.Insert(ResolutionInputRecord{EventID: "$a", EventType: "m.room.create"})
	if got, want := x.String(), "zDnrgYKfPuS6ztctVfakvKVx6rM7l8QVDUuGXcibrnE"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
