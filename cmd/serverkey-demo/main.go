package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gomatrixlib/cuckoo"
	"gomatrixlib/fndsa512"
	"gomatrixlib/keyid"
	"gomatrixlib/matrixjson"
	"gomatrixlib/serverkey"
)

func main() {
	serverName := flag.String("server", "example.com", "Matrix server_name to bind into the self-signed key object")
	validDays := flag.Int("valid-days", 7, "validity window in days")
	edgeBits := flag.Uint("pow-edge-bits", 8, "demo Cuckoo edge bits; production profile uses 29")
	proofSize := flag.Int("pow-proof-size", 4, "demo Cuckoo proof size; production profile uses 42")
	maxNonce := flag.Uint("pow-max-nonce", 1<<12, "maximum edge nonce to search per graph")
	maxGraphNonce := flag.Uint64("pow-max-graph-nonce", 256, "maximum graph nonce attempts")
	flag.Parse()

	priv, pub, err := fndsa512.GenerateKey(nil)
	if err != nil {
		fatal(err)
	}

	validUntil := time.Now().Add(time.Duration(*validDays) * 24 * time.Hour).UnixMilli()
	metadata := serverkey.FNDSAMetadata{
		FIPS206Revision: serverkey.DefaultFIPSRevision,
		Claims:          []string{"constant-time-keygen", "constant-time-signing"},
	}

	obj, keyName, err := serverkey.NewSignedFNDSA(nil, *serverName, priv, pub, validUntil, metadata)
	if err != nil {
		fatal(err)
	}

	verifiedKeyName, err := serverkey.VerifyFNDSASelfSignature(obj, *serverName)
	if err != nil {
		fatal(err)
	}
	if verifiedKeyName != keyName {
		fatal(fmt.Errorf("verified key mismatch: got %s want %s", verifiedKeyName, keyName))
	}

	keyObject := obj["verify_keys"].(map[string]any)[keyName].(map[string]any)
	metadataDigest, err := serverkey.KeyMetadataSHA256(keyObject)
	if err != nil {
		fatal(err)
	}

	keyIDSHA256 := serverkey.KeyIDSHA256(pub)
	challengeObject, proofObject, err := solvePublicationPoW(*serverName, keyIDSHA256, metadataDigest, metadata, validUntil, cuckoo.Config{
		EdgeBits:  *edgeBits,
		ProofSize: *proofSize,
	}, uint32(*maxNonce), *maxGraphNonce)
	if err != nil {
		fatal(err)
	}

	bundle := map[string]any{
		"server_key_object": obj,
		"pow_challenge":     challengeObject,
		"pow_proof":         proofObject,
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	fmt.Printf("server_name: %s\n", *serverName)
	fmt.Printf("key_name: %s\n", keyName)
	fmt.Printf("short_id: %s\n", keyid.ShortID(pub))
	fmt.Printf("key_id_sha256: %s\n", keyIDSHA256)
	fmt.Printf("key_metadata_sha256: %s\n", metadataDigest)
	fmt.Printf("pow_algorithm: %s\n", challengeObject["algorithm"])
	fmt.Printf("pow_graph_nonce: %v\n", proofObject["nonce"])
	fmt.Printf("private_key_base64: %s\n", base64.RawStdEncoding.EncodeToString(priv))
	fmt.Println("publication_bundle:")
	if err := enc.Encode(bundle); err != nil {
		fatal(err)
	}
}

func solvePublicationPoW(serverName, keyIDSHA256, metadataDigest string, metadata serverkey.FNDSAMetadata, validUntil int64, cfg cuckoo.Config, maxNonce uint32, maxGraphNonce uint64) (map[string]any, map[string]any, error) {
	challenge, err := randomChallenge()
	if err != nil {
		return nil, nil, err
	}

	algorithm := fmt.Sprintf("demo.cuckoo-cycle-%d-%d-sha256", cfg.ProofSize, cfg.EdgeBits)
	challengeObject := map[string]any{
		"algorithm":  algorithm,
		"challenge":  challenge,
		"expires_ts": validUntil,
		"resource": map[string]any{
			"action":               "fn-dsa-key-publication",
			"server_name":          serverName,
			"key_id_sha256":        keyIDSHA256,
			"key_metadata_sha256":  metadataDigest,
			"claims":               metadata.Claims,
			"fips_206_revision":    metadata.FIPS206Revision,
			"demo_pow_profile":     true,
			"production_algorithm": "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256",
		},
	}

	canonicalChallenge, err := matrixjson.Canonical(challengeObject)
	if err != nil {
		return nil, nil, err
	}

	for graphNonce := uint64(0); graphNonce < maxGraphNonce; graphNonce++ {
		seed := cuckoo.GraphSeed(canonicalChallenge, graphNonce)
		proof, err := cuckoo.FindProof(cfg, seed[:], maxNonce)
		if err == cuckoo.ErrNoSolution {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if err := cuckoo.Verify(cfg, seed[:], proof); err != nil {
			return nil, nil, err
		}

		solution := make([]any, len(proof))
		for i, nonce := range proof {
			solution[i] = nonce
		}
		return challengeObject, map[string]any{
			"algorithm": challengeObject["algorithm"],
			"challenge": challenge,
			"nonce":     graphNonce,
			"solution":  solution,
		}, nil
	}

	return nil, nil, cuckoo.ErrNoSolution
}

func randomChallenge() (string, error) {
	var challenge [16]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(challenge[:]), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
