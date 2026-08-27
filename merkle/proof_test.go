package merkle

import "testing"

func sampleHeaderFields() []Field {
	return []Field{
		{Name: "room_id", Value: "!room:example.org"},
		{Name: "sender_localpart", Value: "alice"},
		{Name: "sender_domain", Value: "example.org"},
		{Name: "type", Value: "m.room.message"},
		{Name: "state_key", Value: nil},
		{Name: "redacts", Value: nil},
		{Name: "depth", Value: 42},
		{Name: "origin_server_ts", Value: 123456789},
	}
}

func TestLeafPathReconstructsRoot(t *testing.T) {
	fields := sampleHeaderFields()
	root, err := Root(fields)
	if err != nil {
		t.Fatal(err)
	}

	for _, f := range fields {
		path, provedRoot, err := LeafPath(fields, f.Name)
		if err != nil {
			t.Fatalf("LeafPath(%s): %v", f.Name, err)
		}
		if provedRoot != root {
			t.Fatalf("LeafPath(%s) root = %x, want %x", f.Name, provedRoot, root)
		}
		leafHash, err := FieldLeafHash(f)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyLeafPath(leafHash, path, root) {
			t.Fatalf("VerifyLeafPath failed for field %s", f.Name)
		}
	}
}

func TestLeafPathMatchesDraftSenderDomainExample(t *testing.T) {
	// The draft's proof example discloses sender_domain with a 3-step path
	// (right, right, left) over this exact 8-field header.
	fields := sampleHeaderFields()
	path, _, err := LeafPath(fields, "sender_domain")
	if err != nil {
		t.Fatal(err)
	}
	if len(path) != 3 {
		t.Fatalf("path length = %d, want 3", len(path))
	}
	wantSides := []string{"right", "right", "left"}
	for i, step := range path {
		if step.Side != wantSides[i] {
			t.Fatalf("path[%d].Side = %s, want %s", i, step.Side, wantSides[i])
		}
	}
}

func TestVerifyLeafPathRejectsTamperedSibling(t *testing.T) {
	fields := sampleHeaderFields()
	root, err := Root(fields)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := LeafPath(fields, "type")
	if err != nil {
		t.Fatal(err)
	}
	leafHash, err := FieldLeafHash(Field{Name: "type", Value: "m.room.message"})
	if err != nil {
		t.Fatal(err)
	}
	path[0].Hash[0] ^= 0xFF
	if VerifyLeafPath(leafHash, path, root) {
		t.Fatal("tampered sibling should not verify")
	}
}

func TestVerifyLeafPathRejectsUnknownSide(t *testing.T) {
	fields := sampleHeaderFields()
	root, err := Root(fields)
	if err != nil {
		t.Fatal(err)
	}
	path, _, err := LeafPath(fields, "type")
	if err != nil {
		t.Fatal(err)
	}
	leafHash, err := FieldLeafHash(Field{Name: "type", Value: "m.room.message"})
	if err != nil {
		t.Fatal(err)
	}
	path[0].Side = "up"
	if VerifyLeafPath(leafHash, path, root) {
		t.Fatal("unknown side should not verify")
	}
}

func TestLeafPathRejectsUnknownField(t *testing.T) {
	if _, _, err := LeafPath(sampleHeaderFields(), "nonexistent"); err == nil {
		t.Fatal("expected error for unknown field")
	}
}
