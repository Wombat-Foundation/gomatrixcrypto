// Package meanminer shells out to a prebuilt binary wrapping John Tromp's
// reference "mean" (bucket-sort) Cuckoo Cycle solver — see solve_main.cpp
// and external/cuckoo (vendored submodule) — for the one profile where a
// pure-Go solver is too slow to be practical: EdgeBits=29, ProofSize=42
// (tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256).
//
// The binary is built separately (run `make` in this directory) rather
// than compiled in by `go build`, so this package is plain Go: no cgo, no
// C++ toolchain required to build gomatrixlib itself. Callers should
// check Available() and fall back to cuckoo.FindProof when the binary
// hasn't been built.
package meanminer

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const binaryName = "cuckoo_solve_29_42"

// BinaryPath returns the expected path to the compiled solver binary,
// resolved relative to this package's own source directory so it works
// regardless of the caller's working directory.
func BinaryPath() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("meanminer: cannot resolve package directory")
	}
	return filepath.Join(filepath.Dir(file), binaryName), nil
}

// Available reports whether the solver binary has been built.
func Available() bool {
	bin, err := BinaryPath()
	if err != nil {
		return false
	}
	info, err := os.Stat(bin)
	return err == nil && !info.IsDir()
}

// Solve runs the reference EdgeBits=29/ProofSize=42 solver against the
// given 32-byte graph_seed, using nthreads worker threads (0 lets the
// solver pick based on available cores). It returns the found proof's 42
// edge nonces (not necessarily sorted — callers must sort before
// cuckoo.Verify, which requires ascending order), or ok=false if this
// graph has no 42-cycle.
func Solve(seed []byte, nthreads int) (proof []uint32, ok bool, err error) {
	if len(seed) != 32 {
		return nil, false, fmt.Errorf("meanminer: seed must be 32 bytes, got %d", len(seed))
	}
	bin, err := BinaryPath()
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

	out, err := exec.Command(bin, args...).Output()
	if err != nil {
		return nil, false, fmt.Errorf("meanminer: running %s: %w", bin, err)
	}

	lines := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	switch strings.TrimSpace(lines[0]) {
	case "NOSOL":
		return nil, false, nil
	case "SOLVED":
		if len(lines) < 2 {
			return nil, false, fmt.Errorf("meanminer: missing proof line in output %q", out)
		}
		fields := strings.Fields(lines[1])
		proof = make([]uint32, len(fields))
		for i, f := range fields {
			v, perr := strconv.ParseUint(f, 10, 32)
			if perr != nil {
				return nil, false, fmt.Errorf("meanminer: bad nonce %q: %w", f, perr)
			}
			proof[i] = uint32(v)
		}
		return proof, true, nil
	default:
		return nil, false, fmt.Errorf("meanminer: unexpected output %q", out)
	}
}
