package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"

	"gomatrixlib/cuckoo/meanminer"
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
		fmt.Fprintln(stderr, err)
		return 1
	}

	for graphNonce := *start; graphNonce < *start+*limit; graphNonce++ {
		var nonceBytes [8]byte
		binary.LittleEndian.PutUint64(nonceBytes[:], graphNonce)
		sum := sha256.Sum256(append([]byte(*prefix), nonceBytes[:]...))

		proof, ok, err := solve(sum[:], *threads)
		if err != nil {
			fmt.Fprintf(stderr, "nonce %d: %v\n", graphNonce, err)
			return 1
		}
		if !ok {
			fmt.Fprintf(stderr, "attempt %d: no solution, trying next graph nonce\n", graphNonce)
			continue
		}

		fmt.Fprintf(stdout, "FOUND at nonce %d\n", graphNonce)
		fmt.Fprintf(stdout, "%v\n", proof)
		return 0
	}

	fmt.Fprintln(stdout, "no solution found in range")
	return 2
}
