package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo"
	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo/meanminer"
	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/serverkey"
)

const demoPoWProfileNote = "demo-only low-difficulty Cuckoo profile; not valid for production key minting"

const maxProtocolMintingNonce = uint64(1<<32 - 1)

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
	powAlgorithm := flag.String("pow-algorithm", "", "minting proof algorithm for -pow-profile custom")
	demoProfile := flag.Bool("pow-demo-profile", true, "mark -pow-profile custom output as demo-only")
	maxNonce := flag.Uint("pow-max-nonce", 1<<12, "maximum edge nonce to search per minting nonce")
	startMintingNonce := flag.Uint64("pow-start-graph-nonce", 0, "first graph nonce to try")
	maxMintingNonce := flag.Uint64("pow-max-graph-nonce", 256, "exclusive graph-nonce limit")
	privateKeyPassphraseEnv := flag.String("private-key-passphrase-env", "", "environment variable containing a passphrase for encrypted private-key output")
	privateKeyPassphraseFile := flag.String("private-key-passphrase-file", "", "file containing a passphrase for encrypted private-key output")
	flag.Parse()
	if uint64(*maxNonce) > maxProtocolMintingNonce {
		fatal(fmt.Errorf("pow-max-nonce %d exceeds the uint32 edge-nonce limit", *maxNonce))
	}
	if err := validateMintingNonceRange(*startMintingNonce, *maxMintingNonce); err != nil {
		fatal(err)
	}

	profile, err := configurePoWProfile(*profileName, *edgeBits, *proofSize, *powAlgorithm, *demoProfile)
	if err != nil {
		fatal(err)
	}

	passphrase, err := privateKeyPassphrase(*privateKeyPassphraseEnv, *privateKeyPassphraseFile)
	if err != nil {
		fatal(err)
	}

	priv, pub, err := fndsa512.GenerateKey(nil)
	if err != nil {
		fatal(err)
	}
	var encryptedPrivateKey map[string]any
	if len(passphrase) > 0 {
		encryptedPrivateKey, err = serverkey.EncryptPrivateKey(nil, priv, passphrase, serverkey.DefaultPrivateKeyEncryptionParams())
		if err != nil {
			fatal(err)
		}
	}

	proof, keyID, err := solveMintingPoW(*serverName, pub, profile, uint32(*maxNonce), uint32(*startMintingNonce), uint32(*maxMintingNonce))
	if err != nil {
		fatal(err)
	}

	validUntil := time.Now().Add(time.Duration(*validDays) * 24 * time.Hour).UnixMilli()
	metadata := serverkey.FNDSAMetadata{
		FIPS206Revision: serverkey.DefaultFIPSRevision,
		Claims:          []string{"constant-time-keygen", "constant-time-signing"},
	}

	obj, keyName, err := serverkey.NewSignedFNDSA(nil, *serverName, priv, pub, validUntil, metadata, proof)
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
	serverKeyPackageDigest, err := serverKeyPackageSHA256(obj)
	if err != nil {
		fatal(err)
	}

	bundle := map[string]any{
		"server_key_object": obj,
	}
	if profile.Note != "" {
		bundle["pow_profile_note"] = profile.Note
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	fmt.Printf("server_name: %s\n", *serverName)
	fmt.Printf("key_name: %s\n", keyName)
	fmt.Printf("short_key_id: %s\n", keyName[len(serverkey.FNDSAAlgorithm)+1:])
	fmt.Printf("key_id: %s\n", keyID)
	fmt.Printf("key_metadata_sha256: %s\n", metadataDigest)
	fmt.Printf("server_key_package_sha256: %s\n", serverKeyPackageDigest)
	fmt.Printf("profile: %s\n", proof.Algorithm)
	if profile.Note != "" {
		fmt.Printf("pow_profile_note: %s\n", profile.Note)
	}
	fmt.Printf("pow_nonce: %v\n", proof.Nonce)
	if encryptedPrivateKey != nil {
		fmt.Println("encrypted_private_key:")
		if err := enc.Encode(encryptedPrivateKey); err != nil {
			fatal(err)
		}
	} else {
		fmt.Printf("private_key_base64: %s\n", base64.RawStdEncoding.EncodeToString(priv))
	}
	fmt.Println("server_key_response:")
	if err := enc.Encode(bundle); err != nil {
		fatal(err)
	}
}

// validateMintingNonceRange validates an exclusive graph-nonce range.
func validateMintingNonceRange(start, limit uint64) error {
	if start > maxProtocolMintingNonce || limit > maxProtocolMintingNonce+1 || start > limit {
		return fmt.Errorf("invalid graph nonce range [%d, %d): require uint32 nonces and start <= limit", start, limit)
	}
	return nil
}

func privateKeyPassphrase(envName, fileName string) ([]byte, error) {
	if envName != "" && fileName != "" {
		return nil, fmt.Errorf("use only one of -private-key-passphrase-env or -private-key-passphrase-file")
	}
	if envName != "" {
		passphrase, ok := os.LookupEnv(envName)
		if !ok {
			return nil, fmt.Errorf("environment variable %s is not set", envName)
		}
		return []byte(passphrase), nil
	}
	if fileName != "" {
		passphrase, err := os.ReadFile(fileName)
		if err != nil {
			return nil, err
		}
		return []byte(strings.TrimRight(string(passphrase), "\r\n")), nil
	}
	return nil, nil
}

func configurePoWProfile(name string, edgeBits uint, proofSize int, algorithm string, demo bool) (powProfile, error) {
	switch name {
	case "demo":
		cfg := cuckoo.Config{EdgeBits: edgeBits, ProofSize: proofSize}
		return powProfile{
			Algorithm: fmt.Sprintf("demo.cuckoo-cycle-%d-%d-sha3-256-cogen", cfg.ProofSize, cfg.EdgeBits),
			Config:    cfg,
			Demo:      true,
			Note:      demoPoWProfileNote,
		}, nil
	case "production":
		return powProfile{
			Algorithm: serverkey.ProductionPoW,
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

func solveMintingPoW(serverName string, publicKey []byte, profile powProfile, maxNonce, startMintingNonce, maxMintingNonce uint32) (serverkey.FNDSAMintingProof, string, error) {
	useMeanMiner := profile.Config.EdgeBits == 29 && profile.Config.ProofSize == 42 && meanminer.Available()

	for nonce := startMintingNonce; nonce < maxMintingNonce; nonce++ {
		seed, err := serverkey.GraphSeed(publicKey, serverName, profile.Algorithm, nonce)
		if err != nil {
			return serverkey.FNDSAMintingProof{}, "", err
		}

		var proof []uint32
		if useMeanMiner {
			fmt.Fprintf(os.Stderr, "[nonce %d] meanminer: solving EdgeBits=29 ProofSize=42\n", nonce)
			p, ok, err := meanminer.Solve(seed[:], 0)
			if err != nil {
				return serverkey.FNDSAMintingProof{}, "", err
			}
			if !ok {
				continue
			}
			slices.Sort(p)
			proof = p
		} else {
			p, err := cuckoo.FindProof(profile.Config, seed[:], maxNonce, func(msg string) {
				fmt.Fprintf(os.Stderr, "[nonce %d] %s\n", nonce, msg)
			})
			if err == cuckoo.ErrNoSolution {
				continue
			}
			if err != nil {
				return serverkey.FNDSAMintingProof{}, "", err
			}
			proof = p
		}

		if err := cuckoo.Verify(profile.Config, seed[:], proof); err != nil {
			return serverkey.FNDSAMintingProof{}, "", err
		}

		mintingProof := serverkey.FNDSAMintingProof{
			Algorithm: profile.Algorithm,
			Nonce:     nonce,
			Solution:  proof,
		}
		keyID, err := serverkey.KeyIDBase64(publicKey, serverName, mintingProof)
		if err != nil {
			return serverkey.FNDSAMintingProof{}, "", err
		}
		return mintingProof, keyID, nil
	}

	return serverkey.FNDSAMintingProof{}, "", cuckoo.ErrNoSolution
}

func serverKeyPackageSHA256(obj map[string]any) (string, error) {
	signingBytes, err := serverkey.SigningBytes(obj)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(signingBytes)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
