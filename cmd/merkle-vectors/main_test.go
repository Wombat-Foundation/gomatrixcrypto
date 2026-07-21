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

	const want = `[msc4511-merkle]
field_root_hex = 08e7c748acbe75a855a5c1420ea3d5948a765509f27d132796bfbaecbe8c3fae
event_header_root_hex = f4f5f542c8adb6ba354328dfeda66fd069b77981a5514bb86cb22072d5117324
prev_events_hash_hex = fe8934c852d5a646390f3734f99911606c40f4f8ca7fe4065814081e2fb1faef
auth_events_hash_hex = 2309b8433c96de36d4a55cfb263f3f3131a0874324a9bda59bfd9e73e3846ea1
content_hash_hex = 8bfc6857f7a86d45b263c551057d052dfa73ef29dee6e842c90d12143abec729
other_signed_fields_hash_hex = 272428680275d80a8b02254dbbbe13e93af0153a6e8d80746d7d95dd1df48d59
event_root_hex = 734aaf66da440dfbbe445bfe7874014983beafe7682b456f40973f7e8e0a2e4d
event_id = $c0qvZtpEDfu-RFv-eHQBSYO-r-doK0VvQJc_fo4KLk0
`
	if got := buf.String(); got != want {
		t.Fatalf("vector output mismatch:\ngot:\n%s\nwant:\n%s", got, want)
	}
}
