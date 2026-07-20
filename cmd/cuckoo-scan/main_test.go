package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestRunFindsProof(t *testing.T) {
	var stdout, stderr bytes.Buffer
	var calls int
	code := run(
		[]string{"-prefix", "test", "-start", "7", "-limit", "3", "-threads", "2"},
		&stdout,
		&stderr,
		func(seed []byte, nthreads int) ([]uint32, bool, error) {
			calls++
			if len(seed) != 32 {
				t.Fatalf("seed length: got %d", len(seed))
			}
			if nthreads != 2 {
				t.Fatalf("threads mismatch: got %d", nthreads)
			}
			if calls == 2 {
				return []uint32{1, 2, 3}, true, nil
			}
			return nil, false, nil
		},
	)
	if code != 0 {
		t.Fatalf("exit code mismatch: got %d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "FOUND at nonce 8") || !strings.Contains(stdout.String(), "[1 2 3]") {
		t.Fatalf("stdout mismatch: %s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "attempt 7: no solution") {
		t.Fatalf("stderr mismatch: %s", stderr.String())
	}
}

func TestRunReportsNoSolutionAndSolverError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-limit", "2"}, &stdout, &stderr, func([]byte, int) ([]uint32, bool, error) {
		return nil, false, nil
	})
	if code != 2 {
		t.Fatalf("exit code mismatch: got %d", code)
	}
	if !strings.Contains(stdout.String(), "no solution found in range") {
		t.Fatalf("stdout mismatch: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{"-start", "9", "-limit", "1"}, &stdout, &stderr, func([]byte, int) ([]uint32, bool, error) {
		return nil, false, errors.New("solver failed")
	})
	if code != 1 {
		t.Fatalf("exit code mismatch: got %d", code)
	}
	if !strings.Contains(stderr.String(), "nonce 9: solver failed") {
		t.Fatalf("stderr mismatch: %s", stderr.String())
	}
}

func TestRunRejectsBadFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-unknown"}, &stdout, &stderr, nil)
	if code != 1 {
		t.Fatalf("exit code mismatch: got %d", code)
	}
	if !strings.Contains(stderr.String(), "flag provided but not defined") {
		t.Fatalf("stderr mismatch: %s", stderr.String())
	}
}
