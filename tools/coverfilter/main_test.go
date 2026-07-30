package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRunHandlesSameInputAndOutputPath(t *testing.T) {
	dir := t.TempDir()
	profile := filepath.Join(dir, "coverage.out")
	input := "mode: set\ngithub.com/Wombat-Foundation/gomatrixcrypto/tools/coverfilter/main.go:1.1,1.10 1 1\n"
	if err := os.WriteFile(profile, []byte(input), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	initialInfo, err := os.Stat(profile)
	if err != nil {
		t.Fatalf("stat profile after write: %v", err)
	}

	if err := run(profile, profile, "github.com/Wombat-Foundation/gomatrixcrypto", "coverage:ignore"); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	info, err := os.Stat(profile)
	if err != nil {
		t.Fatalf("stat profile: %v", err)
	}
	if got := info.Mode().Perm(); got != initialInfo.Mode().Perm() {
		t.Fatalf("unexpected mode: %v", got)
	}

	output, err := os.ReadFile(profile)
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	if string(output) != input {
		t.Fatalf("unexpected filtered profile:\n%s", output)
	}
}
