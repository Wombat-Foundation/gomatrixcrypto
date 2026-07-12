package main

import (
	"crypto/rand"
	"crypto/sha256"
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

const (
	productionPoWAlgorithm = "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha256"
	demoPoWProfileNote     = "demo-only low-difficulty Cuckoo profile; not valid for production key publication"
)

type powProfile struct {
	Algorithm string
	Config    cuckoo.Config
	Demo      bool
	Note      string
}

func main() {
	serverName := flag.String("server", "example.com", "Matrix server_name to bind into the self-signed key object")
	validDays := flag.Int("valid-days", 7, "validity window in days")
	profileName := flag.String("pow-profile", "demo", "PoW profile: demo, production, or custom")
	edgeBits := flag.Uint("pow-edge-bits", 8, "Cuckoo edge bits; ignored by -pow-profile production")
	proofSize := flag.Int("pow-proof-size", 4, "Cuckoo proof size; ignored by -pow-profile production")
	powAlgorithm := flag.String("pow-algorithm", "", "challenge algorithm for -pow-profile custom")
	demoProfile := flag.Bool("pow-demo-profile", true, "mark -pow-profile custom output as demo-only")
	maxNonce := flag.Uint("pow-max-nonce", 1<<12, "maximum edge nonce to search per graph")
	maxGraphNonce := flag.Uint64("pow-max-graph-nonce", 256, "maximum graph nonce attempts")
	flag.Parse()
	profile, err := configurePoWProfile(*profileName, *edgeBits, *proofSize, *powAlgorithm, *demoProfile)
	if err != nil {
		fatal(err)
	}

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
	serverKeyObjectDigest, err := canonicalSHA256(obj)
	if err != nil {
		fatal(err)
	}

	keyIDSHA256 := serverkey.KeyIDSHA256(pub)
	challengeObject, proofObject, err := solvePublicationPoW(*serverName, keyIDSHA256, metadataDigest, serverKeyObjectDigest, metadata, validUntil, profile, uint32(*maxNonce), *maxGraphNonce)
	if err != nil {
		fatal(err)
	}

	bundle := map[string]any{
		"server_key_object": obj,
		"pow_challenge":     challengeObject,
		"pow_proof":         proofObject,
	}
	if profile.Note != "" {
		bundle["pow_profile_note"] = profile.Note
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	fmt.Printf("server_name: %s\n", *serverName)
	fmt.Printf("key_name: %s\n", keyName)
	fmt.Printf("short_id: %s\n", keyid.ShortID(pub))
	fmt.Printf("key_id_sha256: %s\n", keyIDSHA256)
	fmt.Printf("key_metadata_sha256: %s\n", metadataDigest)
	fmt.Printf("server_key_object_sha256: %s\n", serverKeyObjectDigest)
	fmt.Printf("pow_algorithm: %s\n", challengeObject["algorithm"])
	if profile.Note != "" {
		fmt.Printf("pow_profile_note: %s\n", profile.Note)
	}
	fmt.Printf("pow_graph_nonce: %v\n", proofObject["nonce"])
	fmt.Printf("private_key_base64: %s\n", base64.RawStdEncoding.EncodeToString(priv))
	fmt.Println("publication_bundle:")
	if err := enc.Encode(bundle); err != nil {
		fatal(err)
	}
}

func configurePoWProfile(name string, edgeBits uint, proofSize int, algorithm string, demo bool) (powProfile, error) {
	switch name {
	case "demo":
		cfg := cuckoo.Config{EdgeBits: edgeBits, ProofSize: proofSize}
		return powProfile{
			Algorithm: fmt.Sprintf("demo.cuckoo-cycle-%d-%d-sha256", cfg.ProofSize, cfg.EdgeBits),
			Config:    cfg,
			Demo:      true,
			Note:      demoPoWProfileNote,
		}, nil
	case "production":
		return powProfile{
			Algorithm: productionPoWAlgorithm,
			Config:    cuckoo.Config{EdgeBits: 29, ProofSize: 42},
			Demo:      false,
		}, nil
	case "custom":
		if algorithm == "" {
			return powProfile{}, fmt.Errorf("-pow-algorithm is required with -pow-profile custom")
		}
		profile := powProfile{
			Algorithm: algorithm,
			Config:    cuckoo.Config{EdgeBits: edgeBits, ProofSize: proofSize},
			Demo:      demo,
		}
		if demo {
			profile.Note = demoPoWProfileNote
		}
		return profile, nil
	default:
		return powProfile{}, fmt.Errorf("unknown -pow-profile %q", name)
	}
}

func solvePublicationPoW(serverName, keyIDSHA256, metadataDigest, serverKeyObjectDigest string, metadata serverkey.FNDSAMetadata, validUntil int64, profile powProfile, maxNonce uint32, maxGraphNonce uint64) (map[string]any, map[string]any, error) {
	challenge, err := randomChallenge()
	if err != nil {
		return nil, nil, err
	}

	challengeObject := map[string]any{
		"algorithm":  profile.Algorithm,
		"challenge":  challenge,
		"expires_ts": validUntil,
		"resource": map[string]any{
			"action":                   "fn-dsa-key-publication",
			"server_name":              serverName,
			"key_id_sha256":            keyIDSHA256,
			"key_metadata_sha256":      metadataDigest,
			"server_key_object_sha256": serverKeyObjectDigest,
			"claims":                   metadata.Claims,
			"fips_206_revision":        metadata.FIPS206Revision,
			"production_algorithm":     productionPoWAlgorithm,
		},
	}
	if profile.Demo {
		resource := challengeObject["resource"].(map[string]any)
		resource["demo_pow_profile"] = true
		resource["profile_note"] = profile.Note
	}

	canonicalChallenge, err := matrixjson.Canonical(challengeObject)
	if err != nil {
		return nil, nil, err
	}

	for graphNonce := uint64(0); graphNonce < maxGraphNonce; graphNonce++ {
		seed := cuckoo.GraphSeed(canonicalChallenge, graphNonce)
		proof, err := cuckoo.FindProof(profile.Config, seed[:], maxNonce)
		if err == cuckoo.ErrNoSolution {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if err := cuckoo.Verify(profile.Config, seed[:], proof); err != nil {
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

func canonicalSHA256(v any) (string, error) {
	canonical, err := matrixjson.Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
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
