package merkle

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

func sampleFields() []Field {
	return []Field{
		{Name: "event_id", Value: "$b:example.org"},
		{Name: "depth", Value: int64(7)},
		{Name: "rejected", Value: false},
		{Name: "prev_events_hash", Value: "sha256:abc"},
	}
}

func TestRootIsOrderIndependent(t *testing.T) {
	fields := sampleFields()
	root1, err := Root(fields)
	if err != nil {
		t.Fatal(err)
	}

	slices.Reverse(fields)
	root2, err := Root(fields)
	if err != nil {
		t.Fatal(err)
	}

	if root1 != root2 {
		t.Fatalf("roots differ after reorder: %x != %x", root1, root2)
	}
}

func TestRootStableVector(t *testing.T) {
	root, err := Root(sampleFields())
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(root[:])
	const want = "08e7c748acbe75a855a5c1420ea3d5948a765509f27d132796bfbaecbe8c3fae"
	if got != want {
		t.Fatalf("root mismatch: got %s want %s", got, want)
	}
}

func TestHeaderRootUsesNullForMissingOptionalFields(t *testing.T) {
	root, err := HeaderRoot(Header{
		RoomID:         "!room:example.org",
		Sender:         "@alice:example.org",
		Type:           "m.room.message",
		Depth:          42,
		OriginServerTS: 123456789,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(root[:])
	const want = "f4f5f542c8adb6ba354328dfeda66fd069b77981a5514bb86cb22072d5117324"
	if got != want {
		t.Fatalf("header root mismatch: got %s want %s", got, want)
	}
}

func TestEventRootAndIDStableVector(t *testing.T) {
	prev, err := ComponentHash("prev_events", []any{"$a:example.org"})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := ComponentHash("auth_events", []any{"$auth:example.org"})
	if err != nil {
		t.Fatal(err)
	}
	header, err := HeaderRoot(Header{
		RoomID:         "!room:example.org",
		Sender:         "@alice:example.org",
		Type:           "m.room.message",
		Depth:          42,
		OriginServerTS: 123456789,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := ComponentHash("content", map[string]any{"body": "hello", "msgtype": "m.text"})
	if err != nil {
		t.Fatal(err)
	}
	other, err := ComponentHash("other_signed_fields", map[string]any{"origin": "example.org"})
	if err != nil {
		t.Fatal(err)
	}

	root := EventRoot(prev, auth, header, content, other)
	gotRoot := hex.EncodeToString(root[:])
	const wantRoot = "734aaf66da440dfbbe445bfe7874014983beafe7682b456f40973f7e8e0a2e4d"
	if gotRoot != wantRoot {
		t.Fatalf("event root mismatch: got %s want %s", gotRoot, wantRoot)
	}
	const wantEventID = "$c0qvZtpEDfu-RFv-eHQBSYO-r-doK0VvQJc_fo4KLk0"
	if got := EventID(root); got != wantEventID {
		t.Fatalf("event ID mismatch: got %s want %s", got, wantEventID)
	}
}

func TestDuplicateFieldRejected(t *testing.T) {
	_, err := Root([]Field{
		{Name: "depth", Value: int64(1)},
		{Name: "depth", Value: int64(2)},
	})
	if !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("expected duplicate field error, got %v", err)
	}
}

func TestEmptyRootRejected(t *testing.T) {
	_, err := Root(nil)
	if !errors.Is(err, ErrNoLeaves) {
		t.Fatalf("expected no leaves error, got %v", err)
	}
}

func TestRootFromLeavesRejectsNonCanonicalOrder(t *testing.T) {
	z, err := fieldLeaf(Field{Name: "z", Value: int64(1)})
	if err != nil {
		t.Fatal(err)
	}
	a, err := fieldLeaf(Field{Name: "a", Value: int64(2)})
	if err != nil {
		t.Fatal(err)
	}
	_, err = rootFromLeaves([]leaf{z, a})
	if !errors.Is(err, errLeavesNotCanonical) {
		t.Fatalf("expected canonical order error, got %v", err)
	}
}
