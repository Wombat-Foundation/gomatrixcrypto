package merkle

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"
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
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.message",
		Depth:           42,
		OriginServerTS:  123456789,
	})
	if err != nil {
		t.Fatal(err)
	}
	got := hex.EncodeToString(root[:])
	const want = "db91cc8e8d3eb0d13885c32f28dbd4215a111081383e25263749c65d9bf8bc37"
	if got != want {
		t.Fatalf("header root mismatch: got %s want %s", got, want)
	}
}

func TestHeaderRootWithStateKeyAndRedacts(t *testing.T) {
	stateKey := ""
	redacts := "$a:example.org"
	withOptional, err := HeaderRoot(Header{
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.message",
		StateKey:        &stateKey,
		Redacts:         &redacts,
		Depth:           42,
		OriginServerTS:  123456789,
	})
	if err != nil {
		t.Fatal(err)
	}
	withoutOptional, err := HeaderRoot(Header{
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.message",
		Depth:           42,
		OriginServerTS:  123456789,
	})
	if err != nil {
		t.Fatal(err)
	}
	if withOptional == withoutOptional {
		t.Fatal("expected header root to change when optional fields are set")
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
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.message",
		Depth:           42,
		OriginServerTS:  123456789,
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
	const wantRoot = "4ccc880527fe5f97d27a04105bb55e6c6e75d87928e54a6cd2973c224802ce91"
	if gotRoot != wantRoot {
		t.Fatalf("event root mismatch: got %s want %s", gotRoot, wantRoot)
	}
	const wantEventID = "$TMyIBSf-X5fSegQQW7VebG512Hko5Ups0pc8IkgCzpE"
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

func TestInvalidFieldNameRejected(t *testing.T) {
	_, err := Root([]Field{{Name: string([]byte{0xff}), Value: int64(1)}})
	if !errors.Is(err, ErrInvalidFieldName) {
		t.Fatalf("expected invalid field name error, got %v", err)
	}

	_, err = ComponentHash(string([]byte{0xff}), int64(1))
	if !errors.Is(err, ErrInvalidFieldName) {
		t.Fatalf("expected invalid component field name error, got %v", err)
	}
}

func TestNULInFieldNameRejected(t *testing.T) {
	_, err := Root([]Field{{Name: "a\x00b", Value: int64(1)}})
	if !errors.Is(err, ErrInvalidFieldName) {
		t.Fatalf("expected invalid field name error, got %v", err)
	}

	_, err = ComponentHash("a\x00b", int64(1))
	if !errors.Is(err, ErrInvalidFieldName) {
		t.Fatalf("expected invalid component field name error, got %v", err)
	}
}

func TestMerkleRootDoesNotPanicOnEmptyInput(t *testing.T) {
	// merkleRoot is unreachable with empty input via the public API (Root
	// rejects it with ErrNoLeaves); this only guards the private helper
	// against future misuse, not protocol-defined behavior.
	if got := merkleRoot(nil); got != (Hash{}) {
		t.Fatalf("expected zero hash for empty input, got %x", got)
	}
}

func TestMerkleRootSingleLeafReturnsLeafHash(t *testing.T) {
	var leaf Hash
	leaf[0] = 0x42

	if got := merkleRoot([]Hash{leaf}); got != leaf {
		t.Fatalf("expected singleton merkle root to equal the leaf hash, got %x want %x", got, leaf)
	}
}

func TestRootPropagatesCanonicalEncodingError(t *testing.T) {
	_, err := Root([]Field{{Name: "n", Value: 1.5}})
	if !errors.Is(err, matrixjson.ErrUnsupportedType) {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestEmptyRootRejected(t *testing.T) {
	_, err := Root(nil)
	if !errors.Is(err, ErrNoLeaves) {
		t.Fatalf("expected no leaves error, got %v", err)
	}
}

func TestEmptyFieldNameRejected(t *testing.T) {
	_, err := Root([]Field{{Name: "", Value: nil}})
	if !errors.Is(err, ErrEmptyFieldName) {
		t.Fatalf("expected empty field name error, got %v", err)
	}
}

func TestEmptyLeafHashFieldNameRejected(t *testing.T) {
	_, err := leafHash("", []byte("null"))
	if !errors.Is(err, ErrEmptyFieldName) {
		t.Fatalf("expected empty field name error, got %v", err)
	}
}

func TestComponentHashRejectsEmptyName(t *testing.T) {
	_, err := ComponentHash("", int64(1))
	if !errors.Is(err, ErrEmptyFieldName) {
		t.Fatalf("expected empty field name error, got %v", err)
	}
}

func TestComponentHashMatchesLeafHash(t *testing.T) {
	got, err := ComponentHash("depth", int64(42))
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := matrixjson.Canonical(int64(42))
	if err != nil {
		t.Fatal(err)
	}
	want, err := leafHash("depth", canonical)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("component hash mismatch: got %x want %x", got, want)
	}
}
