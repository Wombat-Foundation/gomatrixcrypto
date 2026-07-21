package meanminer

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestAvailableWithDeps(t *testing.T) {
	fileInfo := fakeFileInfo{}
	dirInfo := fakeFileInfo{mode: fs.ModeDir}

	if !availableWithDeps(func() (string, error) { return "/solver", nil }, func(string) (fs.FileInfo, error) { return fileInfo, nil }) {
		t.Fatalf("expected file binary to be available")
	}
	if availableWithDeps(func() (string, error) { return "", errors.New("no path") }, func(string) (fs.FileInfo, error) { return fileInfo, nil }) {
		t.Fatalf("expected path error to be unavailable")
	}
	if availableWithDeps(func() (string, error) { return "/solver", nil }, func(string) (fs.FileInfo, error) { return nil, errors.New("not found") }) {
		t.Fatalf("expected stat error to be unavailable")
	}
	if availableWithDeps(func() (string, error) { return "/solver", nil }, func(string) (fs.FileInfo, error) { return dirInfo, nil }) {
		t.Fatalf("expected directory to be unavailable")
	}
}

func TestSolveWithDepsSolvedAndNoSolution(t *testing.T) {
	seed := make([]byte, 32)
	seed[0] = 0x12
	seed[8] = 0x34
	seed[16] = 0x56
	seed[24] = 0x78

	proof, ok, err := solveWithDeps(seed, 6, fixedBinaryPath, func(path string, args ...string) ([]byte, error) {
		if path != "/solver" {
			t.Fatalf("path mismatch: got %s", path)
		}
		wantArgs := []string{"12", "34", "56", "78", "6"}
		if strings.Join(args, ",") != strings.Join(wantArgs, ",") {
			t.Fatalf("args mismatch: got %v want %v", args, wantArgs)
		}
		return []byte("SOLVED\n3 1 2\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || len(proof) != 3 || proof[0] != 3 || proof[1] != 1 || proof[2] != 2 {
		t.Fatalf("unexpected solved result: proof=%v ok=%v", proof, ok)
	}

	proof, ok, err = solveWithDeps(seed, 0, fixedBinaryPath, func(string, ...string) ([]byte, error) {
		return []byte("NOSOL\n"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if ok || proof != nil {
		t.Fatalf("unexpected no-solution result: proof=%v ok=%v", proof, ok)
	}
}

func TestSolveWithDepsRejectsFailuresAndMalformedOutput(t *testing.T) {
	seed := make([]byte, 32)
	cases := []struct {
		name string
		out  []byte
		err  error
	}{
		{name: "runner error", err: errors.New("exec failed")},
		{name: "missing proof", out: []byte("SOLVED\n")},
		{name: "bad nonce", out: []byte("SOLVED\n1 nope 3\n")},
		{name: "unexpected output", out: []byte("WHAT\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := solveWithDeps(seed, 0, fixedBinaryPath, func(string, ...string) ([]byte, error) {
				return tc.out, tc.err
			})
			if err == nil {
				t.Fatalf("expected error")
			}
		})
	}

	if _, _, err := solveWithDeps(seed, 0, func() (string, error) { return "", errors.New("no path") }, nil); err == nil {
		t.Fatalf("expected binary path error")
	}
}

func fixedBinaryPath() (string, error) {
	return "/solver", nil
}

type fakeFileInfo struct {
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return "solver" }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() any           { return nil }
