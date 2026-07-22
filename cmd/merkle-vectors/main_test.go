package main

import (
	"bytes"
	"io"
	"os"
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

	runErr := run()
	closeErr := w.Close()
	os.Stdout = stdout
	if runErr != nil {
		t.Fatal(runErr)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
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
