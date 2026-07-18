package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"os"

	"gomatrixlib/cuckoo/meanminer"
)

func main() {
	var (
		prefix  = flag.String("prefix", "manual-test", "seed prefix to hash with each graph nonce")
		start   = flag.Uint64("start", 0, "first graph nonce to try")
		limit   = flag.Uint64("limit", 200, "number of graph nonces to try")
		threads = flag.Int("threads", 0, "solver threads; 0 lets the solver choose")
	)
	flag.Parse()

	for graphNonce := *start; graphNonce < *start+*limit; graphNonce++ {
		var nonceBytes [8]byte
		binary.LittleEndian.PutUint64(nonceBytes[:], graphNonce)
		sum := sha256.Sum256(append([]byte(*prefix), nonceBytes[:]...))

		proof, ok, err := meanminer.Solve(sum[:], *threads)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nonce %d: %v\n", graphNonce, err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "attempt %d: no solution, trying next graph nonce\n", graphNonce)
			continue
		}

		fmt.Printf("FOUND at nonce %d\n", graphNonce)
		fmt.Printf("%v\n", proof)
		return
	}

	fmt.Fprintln(os.Stdout, "no solution found in range")
	os.Exit(2)
}
