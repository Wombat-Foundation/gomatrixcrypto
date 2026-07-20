package main

import (
	"os"
	"testing"

	"gomatrixlib/cuckoo"
	"gomatrixlib/serverkey"
)

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

func TestConfigurePoWProfileRejectsInvalidInputs(t *testing.T) {
	if _, err := configurePoWProfile("custom", 8, 4, "", true); err == nil {
		t.Fatalf("expected missing custom algorithm to fail")
	}
	if _, err := configurePoWProfile("unknown", 8, 4, "", true); err == nil {
		t.Fatalf("expected unknown profile to fail")
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
