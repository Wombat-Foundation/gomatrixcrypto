package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestRunOutputsStableVectors(t *testing.T) {
	stdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Stdout = stdout
		_ = r.Close()
		_ = w.Close()
	})
	os.Stdout = w

	runErr := run("")
	closeErr := w.Close()
	if runErr != nil {
		t.Fatalf("run failed: %v", runErr)
	}
	if closeErr != nil {
		t.Fatalf("stdout close failed: %v", closeErr)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("stdout read failed: %v", err)
	}

	const want = `[msc4511-merkle]
field_root_hex = 08e7c748acbe75a855a5c1420ea3d5948a765509f27d132796bfbaecbe8c3fae
event_header_root_hex = db91cc8e8d3eb0d13885c32f28dbd4215a111081383e25263749c65d9bf8bc37
prev_events_hash_hex = fe8934c852d5a646390f3734f99911606c40f4f8ca7fe4065814081e2fb1faef
auth_events_hash_hex = 2309b8433c96de36d4a55cfb263f3f3131a0874324a9bda59bfd9e73e3846ea1
content_hash_hex = 8bfc6857f7a86d45b263c551057d052dfa73ef29dee6e842c90d12143abec729
other_signed_fields_hash_hex = 272428680275d80a8b02254dbbbe13e93af0153a6e8d80746d7d95dd1df48d59
event_root_hex = 4ccc880527fe5f97d27a04105bb55e6c6e75d87928e54a6cd2973c224802ce91
event_id = $TMyIBSf-X5fSegQQW7VebG512Hko5Ups0pc8IkgCzpE
`
	if got := buf.String(); got != want {
		t.Fatalf("vector output mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}

func TestRunWritesOutputFile(t *testing.T) {
	tempDir := t.TempDir()
	outPath := filepath.Join(tempDir, "sub", "vectors.json")
	if err := run(outPath); err != nil {
		t.Fatalf("run failed: %v", err)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	var vecs MerkleVectors
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("failed to unmarshal output file: %v", err)
	}
	if vecs.Schema != "msc4511-merkle-vectors-v1" {
		t.Fatalf("unexpected schema in output file: got %q want %q", vecs.Schema, "msc4511-merkle-vectors-v1")
	}
}
