package main

import (
	"os"
	"testing"
)

func TestReadInputFromFile(t *testing.T) {
	path := t.TempDir() + "/key.txt"
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readInput(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("input mismatch: got %q", got)
	}
}

func TestReadPassphraseFromEnvAndFile(t *testing.T) {
	t.Setenv("SERVERKEY_TEST_PASSPHRASE", "from env")
	got, err := readPassphrase("SERVERKEY_TEST_PASSPHRASE", "", "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from env" {
		t.Fatalf("env passphrase mismatch: got %q", got)
	}

	path := t.TempDir() + "/passphrase"
	if err := os.WriteFile(path, []byte("from file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = readPassphrase("", path, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "from file" {
		t.Fatalf("file passphrase mismatch: got %q", got)
	}
}

func TestReadPassphraseRejectsAmbiguousAndMissingSources(t *testing.T) {
	t.Setenv("SERVERKEY_TEST_PASSPHRASE", "from env")
	path := t.TempDir() + "/passphrase"
	if err := os.WriteFile(path, []byte("from file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPassphrase("SERVERKEY_TEST_PASSPHRASE", path, "new passphrase"); err == nil {
		t.Fatalf("expected ambiguous passphrase sources to fail")
	}
	if _, err := readPassphrase("", "", "new passphrase"); err == nil {
		t.Fatalf("expected missing passphrase source to fail")
	}
	if _, err := readPassphrase("SERVERKEY_TEST_MISSING", "", "passphrase"); err == nil {
		t.Fatalf("expected missing environment variable to fail")
	}
}
