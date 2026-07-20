package meanminer

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryPath(t *testing.T) {
	path, err := BinaryPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != binaryName {
		t.Fatalf("binary path mismatch: got %s", path)
	}
	if !strings.Contains(filepath.ToSlash(path), "cuckoo/meanminer/") {
		t.Fatalf("binary path should resolve relative to package, got %s", path)
	}
}

func TestSolveRejectsInvalidSeedLength(t *testing.T) {
	if _, _, err := Solve([]byte("short"), 0); err == nil {
		t.Fatalf("expected invalid seed length to fail")
	}
}
