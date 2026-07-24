// Package meanminer shells out to a prebuilt binary wrapping John Tromp's
// reference "mean" (bucket-sort) Cuckoo Cycle solver — see solve_main.cpp
// and external/cuckoo (vendored submodule) — for the one profile where a
// pure-Go solver is too slow to be practical: EdgeBits=29, ProofSize=42
// (tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256).
//
// The binary is built separately (run `make` in this directory) rather
// than compiled in by `go build`, so this package is plain Go: no cgo, no
// C++ toolchain required to build gomatrixcrypto itself. Callers should
// check Available() and fall back to cuckoo.FindProof when the binary
// hasn't been built.
package meanminer

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const binaryName = "cuckoo_solve_29_42"

type commandRunner func(path string, args ...string) ([]byte, error)
type binaryPathFunc func() (string, error)
type statFunc func(string) (fs.FileInfo, error)

var runtimeCaller = runtime.Caller
var binaryPathForAvailable = BinaryPath
var statForAvailable = os.Stat

// BinaryPath returns the expected path to the compiled solver binary,
// resolved relative to this package's own source directory so it works
// regardless of the caller's working directory.
func BinaryPath() (string, error) {
	_, file, _, ok := runtimeCaller(0)
	if !ok {
		return "", fmt.Errorf("meanminer: cannot resolve package directory")
	}
	return filepath.Join(filepath.Dir(file), binaryName), nil
}

// Available reports whether the solver binary has been built.
func Available() bool {
	return availableWithDeps(binaryPathForAvailable, statForAvailable)
}

func availableWithDeps(binaryPath binaryPathFunc, stat statFunc) bool {
	bin, err := binaryPath()
	if err != nil {
		return false
	}
	info, err := stat(bin)
	return err == nil && !info.IsDir()
}

// Solve runs the reference EdgeBits=29/ProofSize=42 solver against the
// given 32-byte graph_seed, using nthreads worker threads (0 lets the
// solver pick based on available cores). It returns the found proof's 42
// edge nonces (not necessarily sorted — callers must sort before
// cuckoo.Verify, which requires ascending order), or ok=false if this
// graph has no 42-cycle.
func Solve(seed []byte, nthreads int) (proof []uint32, ok bool, err error) {
	return solveWithDeps(seed, nthreads, BinaryPath, runCommand)
}

func runCommand(path string, args ...string) ([]byte, error) {
	return exec.Command(path, args...).Output()
}

func solveWithDeps(seed []byte, nthreads int, binaryPath binaryPathFunc, run commandRunner) (proof []uint32, ok bool, err error) {
	if len(seed) != 32 {
		return nil, false, fmt.Errorf("meanminer: seed must be 32 bytes, got %d", len(seed))
	}
	bin, err := binaryPath()
	if err != nil {
		return nil, false, err
	}

	var words [4]uint64
	for i := range words {
		words[i] = binary.LittleEndian.Uint64(seed[i*8:])
	}

	args := make([]string, 0, 5)
	for _, w := range words {
		args = append(args, strconv.FormatUint(w, 16))
	}
	if nthreads > 0 {
		args = append(args, strconv.Itoa(nthreads))
	}

	out, err := run(bin, args...)
	if err != nil {
		return nil, false, fmt.Errorf("meanminer: running %s: %w", bin, err)
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	for i, line := range lines {
		switch strings.TrimSpace(line) {
		case "NOSOL":
			return nil, false, nil
		case "SOLVED":
			if i+1 >= len(lines) {
				return nil, false, fmt.Errorf("meanminer: missing proof line in output %q", out)
			}
			fields := strings.Fields(lines[i+1])
			proof = make([]uint32, len(fields))
			for j, f := range fields {
				v, perr := strconv.ParseUint(f, 10, 32)
				if perr != nil {
					return nil, false, fmt.Errorf("meanminer: bad nonce %q: %w", f, perr)
				}
				proof[j] = uint32(v)
			}
			return proof, true, nil
		}
	}

	return nil, false, fmt.Errorf("meanminer: unexpected output %q", out)
}
