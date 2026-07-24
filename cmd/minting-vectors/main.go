package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo"
	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo/meanminer"
	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/serverkey"

	"golang.org/x/crypto/sha3"
)

const (
	keygenSeed = "msc00e4-sha3-256-key-minting-vector-keygen-v1"
)

type shakeReader struct {
	hash sha3.ShakeHash
}

func (r *shakeReader) Read(p []byte) (int, error) {
	return r.hash.Read(p)
}

func deterministicReader(seed string) io.Reader {
	hash := sha3.NewShake256()
	_, _ = hash.Write([]byte(seed))
	return &shakeReader{hash: hash}
}

type vectorEdge struct {
	Nonce uint32 `json:"nonce"`
	U     uint64 `json:"u"`
	V     uint64 `json:"v"`
}

type vectorReproduction struct {
	KeygenSeedASCII string `json:"keygen_seed_ascii"`
	EdgeBits        uint   `json:"edge_bits"`
	ProofSize       int    `json:"proof_size"`
}

type vectorPoW struct {
	Nonce    uint32   `json:"nonce"`
	Solution []uint32 `json:"solution"`
}

type vectorDiagnostics struct {
	Notice                    string             `json:"notice"`
	Reproduction              vectorReproduction `json:"reproduction"`
	GraphSeedWordsUint64LEHex []string           `json:"graph_seed_words_uint64_le_hex"`
	Edges                     []vectorEdge       `json:"edges"`
}

type vector struct {
	Schema                  string            `json:"schema"`
	ServerName              string            `json:"server_name"`
	PublicKeyBase64         string            `json:"public_key_base64"`
	Profile                 string            `json:"profile"`
	PoW                     vectorPoW         `json:"pow"`
	GraphSeedHex            string            `json:"graph_seed_hex"`
	KeyID                   string            `json:"key_id"`
	NoncanonicalDiagnostics vectorDiagnostics `json:"noncanonical_diagnostics"`
}

func generate(serverName string, startNonce, maxNonce uint64, threads int) (vector, error) {
	if !meanminer.Available() {
		return vector{}, fmt.Errorf("production miner is unavailable; build cuckoo/meanminer/csrc")
	}

	_, publicKey, err := fndsa512.GenerateKey(deterministicReader(keygenSeed))
	if err != nil {
		return vector{}, err
	}
	cfg := cuckoo.Config{EdgeBits: 29, ProofSize: 42}
	for nonce := startNonce; nonce < maxNonce; nonce++ {
		fmt.Fprintf(os.Stderr, "mining nonce %d\n", nonce)
		seed, err := serverkey.GraphSeed(publicKey, serverName, serverkey.ProductionProfile, uint32(nonce))
		if err != nil {
			return vector{}, err
		}
		solution, ok, err := meanminer.Solve(seed[:], threads)
		if err != nil {
			return vector{}, err
		}
		if !ok {
			continue
		}
		slices.Sort(solution)
		if err := cuckoo.Verify(cfg, seed[:], solution); err != nil {
			return vector{}, fmt.Errorf("miner returned invalid proof: %w", err)
		}

		proof := serverkey.FNDSAMintingProof{
			Algorithm: serverkey.ProductionPoW,
			Nonce:     uint32(nonce),
			Solution:  solution,
		}
		keyID, err := serverkey.KeyID(publicKey, serverName, proof)
		if err != nil {
			return vector{}, err
		}

		words := make([]string, 4)
		for i := range words {
			words[i] = fmt.Sprintf("%016x", binary.LittleEndian.Uint64(seed[i*8:]))
		}
		edges := make([]vectorEdge, len(solution))
		for i, edgeNonce := range solution {
			edge, err := cuckoo.EdgeForNonce(cfg, seed[:], edgeNonce)
			if err != nil {
				return vector{}, err
			}
			edges[i] = vectorEdge{Nonce: edgeNonce, U: edge.U, V: edge.V}
		}

		return vector{
			Schema:          "msc00e4-sha3-256-cogen-42-29-v1",
			ServerName:      serverName,
			PublicKeyBase64: base64.RawStdEncoding.EncodeToString(publicKey),
			Profile:         serverkey.ProductionProfile,
			PoW: vectorPoW{
				Nonce:    uint32(nonce),
				Solution: solution,
			},
			GraphSeedHex: hex.EncodeToString(seed[:]),
			KeyID:        base64.RawURLEncoding.EncodeToString(keyID[:]),
			NoncanonicalDiagnostics: vectorDiagnostics{
				Notice: "Derived diagnostic and reproduction data; not part of the protocol object or any canonical hash input.",
				Reproduction: vectorReproduction{
					KeygenSeedASCII: keygenSeed,
					EdgeBits:        cfg.EdgeBits,
					ProofSize:       cfg.ProofSize,
				},
				GraphSeedWordsUint64LEHex: words,
				Edges:                     edges,
			},
		}, nil
	}
	return vector{}, cuckoo.ErrNoSolution
}

func main() {
	serverName := flag.String("server-name", "example.com", "server name committed by the minting proof")
	startNonce := flag.Uint64("start-nonce", 0, "first minting nonce to try")
	maxNonce := flag.Uint64("max-nonce", 1024, "exclusive minting nonce limit")
	threads := flag.Int("threads", 0, "miner threads (0 uses available CPUs)")
	output := flag.String("output", "", "write JSON to this path instead of stdout")
	flag.Parse()

	v, err := generate(*serverName, *startNonce, *maxNonce, *threads)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	writer := io.Writer(os.Stdout)
	var outputFile *os.File
	if *output != "" {
		outputFile, err = os.Create(*output)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		writer = outputFile
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if outputFile != nil {
		if err := outputFile.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}
