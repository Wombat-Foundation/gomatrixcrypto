package lthash

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func mustEncodeRecord(t *testing.T, r ResolutionInputRecord) []byte {
	t.Helper()
	encoded, err := r.Encode()
	if err != nil {
		t.Fatalf("Encode(%v) error: %v", r, err)
	}
	return encoded
}

func mustInsertInput(t *testing.T, x *ResolutionInputs, r ResolutionInputRecord) {
	t.Helper()
	if err := x.Insert(r); err != nil {
		t.Fatalf("Insert(%v) error: %v", r, err)
	}
}

func TestResolutionInputEncodingCanonical(t *testing.T) {
	a := ResolutionInputRecord{EventID: "$e", EventType: "m.room.member", StateKey: "@a:x", AuthEvents: []string{"$b", "$a"}}
	b := a
	b.AuthEvents = []string{"$a", "$b"}
	if !bytes.Equal(mustEncodeRecord(t, a), mustEncodeRecord(t, b)) {
		t.Fatal("edge order must not affect encoding")
	}

	want := []byte{2, 0, '$', 'e', 13, 0}
	want = append(want, "m.room.member"...)
	want = append(want, 4, 0)
	want = append(want, "@a:x"...)
	want = append(want, 2, 0, 0, 0, 2, 0, '$', 'a', 2, 0, '$', 'b', 0, 0, 0, 0)
	if got := mustEncodeRecord(t, a); !bytes.Equal(got, want) {
		t.Fatalf("encoding mismatch:\n got %v\nwant %v", got, want)
	}
}

func TestResolutionInputsDistinguishEdgesAndDomain(t *testing.T) {
	base := ResolutionInputRecord{EventID: "$e", EventType: "m.room.name", AuthEvents: []string{"$c"}}
	rewired := base
	rewired.AuthEvents = []string{"$d"}

	var x, y ResolutionInputs
	mustInsertInput(t, &x, base)
	mustInsertInput(t, &y, rewired)
	if x.Digest() == y.Digest() {
		t.Fatal("different edges must be distinct elements")
	}
	if err := x.Remove(base); err != nil {
		t.Fatalf("Remove error: %v", err)
	}
	if x != (ResolutionInputs{}) {
		t.Fatal("insert/remove must round-trip to empty")
	}

	var overlay RedactionOverlay
	overlay.Insert("m.room.name", "", "$e")
	var inputs ResolutionInputs
	mustInsertInput(t, &inputs, ResolutionInputRecord{EventID: "$e", EventType: "m.room.name"})
	if overlay.Digest() == inputs.Digest() {
		t.Fatal("domains must be separated")
	}
}

func TestResolutionInputRejectsOverlongFields(t *testing.T) {
	long := strings.Repeat("a", 1<<16)
	if _, err := (ResolutionInputRecord{EventID: long}).Encode(); !errors.Is(err, ErrResolutionInputTooLong) {
		t.Fatalf("Encode: expected ErrResolutionInputTooLong, got %v", err)
	}
	var x ResolutionInputs
	if err := x.Insert(ResolutionInputRecord{StateKey: long}); !errors.Is(err, ErrResolutionInputTooLong) {
		t.Fatalf("Insert: expected ErrResolutionInputTooLong, got %v", err)
	}
}

// Cross-implementation vector; the same value is pinned in rezzy.
func TestResolutionInputsVector(t *testing.T) {
	var x ResolutionInputs
	mustInsertInput(t, &x, ResolutionInputRecord{EventID: "$e", EventType: "m.room.member", StateKey: "@a:x", AuthEvents: []string{"$b", "$a"}, StatePredecessors: []string{"$p"}})
	mustInsertInput(t, &x, ResolutionInputRecord{EventID: "$a", EventType: "m.room.create"})
	if got, want := x.String(), "zDnrgYKfPuS6ztctVfakvKVx6rM7l8QVDUuGXcibrnE"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// Normative vector from the MSC4500 proposal ("Sibling accumulators").
func TestResolutionInputsProposalVector(t *testing.T) {
	r := ResolutionInputRecord{EventID: "$event_1", EventType: "m.room.member", StateKey: "@alice:example.com"}
	const wantRaw = "0800246576656e745f310d006d2e726f6f6d2e6d656d626572120040616c6963653a6578616d706c652e636f6d0000000000000000"
	if got := hex.EncodeToString(mustEncodeRecord(t, r)); got != wantRaw {
		t.Fatalf("raw element %s want %s", got, wantRaw)
	}
	var x ResolutionInputs
	mustInsertInput(t, &x, r)
	if got, want := x.String(), "IGytaez3uh-Y5gPuZ7o2bZxlaufNhkXH558n-Unor_Y"; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}
