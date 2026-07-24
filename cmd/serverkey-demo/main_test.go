package main

import (
	"errors"
	"io"
	"os"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo"
	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/serverkey"

	"golang.org/x/crypto/sha3"
)

func testRNG(seed string) io.Reader {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte(seed))
	return h
}

func TestPrivateKeyPassphraseSources(t *testing.T) {
	t.Setenv("SERVERKEY_DEMO_TEST_PASSPHRASE", "from env")
	got, err := privateKeyPassphrase("SERVERKEY_DEMO_TEST_PASSPHRASE", "")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from env" {
		t.Fatalf("env passphrase mismatch: got %q", got)
	}

	path := t.TempDir() + "/passphrase"
	if err := os.WriteFile(path, []byte("from file\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = privateKeyPassphrase("", path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from file" {
		t.Fatalf("file passphrase mismatch: got %q", got)
	}

	got, err = privateKeyPassphrase("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil passphrase without a source")
	}
}

func TestPrivateKeyPassphraseRejectsInvalidSources(t *testing.T) {
	t.Setenv("SERVERKEY_DEMO_TEST_PASSPHRASE", "from env")
	path := t.TempDir() + "/passphrase"
	if err := os.WriteFile(path, []byte("from file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := privateKeyPassphrase("SERVERKEY_DEMO_TEST_PASSPHRASE", path); err == nil {
		t.Fatalf("expected ambiguous passphrase sources to fail")
	}
	if _, err := privateKeyPassphrase("SERVERKEY_DEMO_TEST_MISSING", ""); err == nil {
		t.Fatalf("expected missing environment variable to fail")
	}
	if _, err := privateKeyPassphrase("", path+"/missing"); err == nil {
		t.Fatalf("expected missing passphrase file to fail")
	}
}

func TestConfigurePoWProfile(t *testing.T) {
	demo, err := configurePoWProfile("demo", 8, 4, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if demo.Algorithm != "demo.cuckoo-cycle-4-8-sha3-256-cogen" || demo.Config != (cuckoo.Config{EdgeBits: 8, ProofSize: 4}) || !demo.Demo || demo.Note == "" {
		t.Fatalf("unexpected demo profile: %#v", demo)
	}

	production, err := configurePoWProfile("production", 8, 4, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if production.Algorithm != serverkey.ProductionPoW || production.Config != (cuckoo.Config{EdgeBits: 29, ProofSize: 42}) || production.Demo || production.Note != "" {
		t.Fatalf("unexpected production profile: %#v", production)
	}

	custom, err := configurePoWProfile("custom", 12, 6, "local.example", false)
	if err != nil {
		t.Fatal(err)
	}
	if custom.Algorithm != "local.example" || custom.Config != (cuckoo.Config{EdgeBits: 12, ProofSize: 6}) || custom.Demo || custom.Note != "" {
		t.Fatalf("unexpected custom profile: %#v", custom)
	}
}

func TestConfigurePoWProfileCustomDemoSetsNote(t *testing.T) {
	custom, err := configurePoWProfile("custom", 12, 6, "local.example", true)
	if err != nil {
		t.Fatal(err)
	}
	if !custom.Demo || custom.Note == "" {
		t.Fatalf("expected demo note to be set: %#v", custom)
	}
}

func TestConfigurePoWProfileRejectsInvalidInputs(t *testing.T) {
	if _, err := configurePoWProfile("custom", 8, 4, "", true); err == nil {
		t.Fatalf("expected missing custom algorithm to fail")
	}
	if _, err := configurePoWProfile("unknown", 8, 4, "", true); err == nil {
		t.Fatalf("expected unknown profile to fail")
	}
}

// TestValidateMintingNonceLimit checks the exclusive graph-nonce bound.
func TestValidateMintingNonceLimit(t *testing.T) {
	for _, tc := range []struct {
		limit uint64
		valid bool
	}{
		{limit: 0, valid: true},
		{limit: maxProtocolMintingNonce + 1, valid: true},
		{limit: maxProtocolMintingNonce + 2, valid: false},
	} {
		err := validateMintingNonceLimit(tc.limit)
		if (err == nil) != tc.valid {
			t.Fatalf("validateMintingNonceLimit(%d) error = %v, valid = %v", tc.limit, err, tc.valid)
		}
	}
}

func TestServerKeyPackageSHA256(t *testing.T) {
	got, err := serverKeyPackageSHA256(map[string]any{
		"server_name": "example.com",
		"signatures":  map[string]any{"ignored": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "r9nu8FpPssoIAjMRy9lHXbVXblLv5iHmIKcIRAVSfGA" {
		t.Fatalf("digest mismatch: got %s", got)
	}
	if _, err := serverKeyPackageSHA256(map[string]any{"bad": 1.5}); err == nil {
		t.Fatalf("expected unsupported object to fail")
	}
}

func TestSolveMintingPoW(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-demo-pow-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	profile := powProfile{
		Algorithm: "test.cuckoo-cycle-4-8-sha3-256-cogen",
		Config:    cuckoo.Config{EdgeBits: 8, ProofSize: 4},
		Demo:      true,
	}
	proof, keyID, err := solveMintingPoW("example.com", pub, profile, 1<<12, 64)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Algorithm != profile.Algorithm || len(proof.Solution) != 4 || keyID == "" {
		t.Fatalf("unexpected proof result: proof=%#v keyID=%q", proof, keyID)
	}

	seed, err := serverkey.GraphSeed(pub, "example.com", profile.Algorithm, proof.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := cuckoo.Verify(profile.Config, seed[:], proof.Solution); err != nil {
		t.Fatalf("proof failed verification: %v", err)
	}
}

func TestSolveMintingPoWPropagatesGraphSeedError(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-demo-badserver-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	profile := powProfile{
		Algorithm: "test.cuckoo-cycle-4-8-sha3-256-cogen",
		Config:    cuckoo.Config{EdgeBits: 8, ProofSize: 4},
		Demo:      true,
	}
	if _, _, err := solveMintingPoW(string([]byte{0xff}), pub, profile, 1<<12, 64); err == nil {
		t.Fatalf("expected invalid server name to fail")
	}
}

func TestSolveMintingPoWPropagatesFindProofError(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-demo-badconfig-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	profile := powProfile{
		Algorithm: "test.cuckoo-cycle-invalid",
		Config:    cuckoo.Config{EdgeBits: 1, ProofSize: 4},
		Demo:      true,
	}
	if _, _, err := solveMintingPoW("example.com", pub, profile, 1<<12, 64); !errors.Is(err, cuckoo.ErrInvalidEdgeBits) {
		t.Fatalf("expected invalid edge bits, got %v", err)
	}
}

func TestSolveMintingPoWPropagatesKeyIDError(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-demo-badalgo-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	profile := powProfile{
		Algorithm: string([]byte{0xff}),
		Config:    cuckoo.Config{EdgeBits: 8, ProofSize: 4},
		Demo:      true,
	}
	if _, _, err := solveMintingPoW("example.com", pub, profile, 1<<12, 64); err == nil {
		t.Fatalf("expected invalid algorithm string to fail key ID computation")
	}
}

func TestSolveMintingPoWNoSolution(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-demo-nosol-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	profile := powProfile{
		Algorithm: "test.cuckoo-cycle-4-8-sha3-256-cogen",
		Config:    cuckoo.Config{EdgeBits: 8, ProofSize: 4},
		Demo:      true,
	}
	if _, _, err := solveMintingPoW("example.com", pub, profile, 1, 1); err != cuckoo.ErrNoSolution {
		t.Fatalf("expected no solution, got %v", err)
	}
}
