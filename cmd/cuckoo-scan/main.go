package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo/meanminer"
)

func main() {
	code := run(os.Args[1:], os.Stdout, os.Stderr, meanminer.Solve)
	if code != 0 {
		os.Exit(code)
	}
}

type solverFunc func(seed []byte, nthreads int) ([]uint32, bool, error)

func run(args []string, stdout, stderr io.Writer, solve solverFunc) int {
	flags := flag.NewFlagSet("cuckoo-scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	prefix := flags.String("prefix", "manual-test", "seed prefix to hash with each graph nonce")
	start := flags.Uint64("start", 0, "first graph nonce to try")
	limit := flags.Uint64("limit", 200, "number of graph nonces to try")
	threads := flags.Int("threads", 0, "solver threads; 0 lets the solver choose")
	if err := flags.Parse(args); err != nil {
		if err := writeLine(stderr, err); err != nil {
			return 1
		}
		return 1
	}

	for graphNonce := *start; graphNonce < *start+*limit; graphNonce++ {
		var nonceBytes [8]byte
		binary.LittleEndian.PutUint64(nonceBytes[:], graphNonce)
		sum := sha256.Sum256(append([]byte(*prefix), nonceBytes[:]...))

		proof, ok, err := solve(sum[:], *threads)
		if err != nil {
			if err := writef(stderr, "nonce %d: %v\n", graphNonce, err); err != nil {
				return 1
			}
			return 1
		}
		if !ok {
			if err := writef(stderr, "attempt %d: no solution, trying next graph nonce\n", graphNonce); err != nil {
				return 1
			}
			continue
		}

		if err := writef(stdout, "FOUND at nonce %d\n", graphNonce); err != nil {
			return 1
		}
		if err := writef(stdout, "%v\n", proof); err != nil {
			return 1
		}
		return 0
	}

	if err := writeLine(stdout, "no solution found in range"); err != nil {
		return 1
	}
	return 2
}

func writeLine(w io.Writer, a ...any) error {
	_, err := fmt.Fprintln(w, a...)
	return err
}

func writef(w io.Writer, format string, a ...any) error {
	_, err := fmt.Fprintf(w, format, a...)
	return err
}
