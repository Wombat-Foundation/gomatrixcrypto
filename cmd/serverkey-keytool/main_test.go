package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"gomatrixlib/fndsa512"
	"gomatrixlib/serverkey"
)

func TestReadInputFromFile(t *testing.T) {
	path := t.TempDir() + "/key.txt"
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readInput(path, nil)
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

func TestReadInputFromStdin(t *testing.T) {
	got, err := readInput("-", bytes.NewReader([]byte("secret")))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret" {
		t.Fatalf("stdin mismatch: got %q", got)
	}
}

func TestRunEncryptAndReencrypt(t *testing.T) {
	privateKey := bytes.Repeat([]byte{0x42}, fndsa512.PrivateKeySize)
	t.Setenv("SERVERKEY_TEST_PASSPHRASE", "old passphrase")

	var encryptedOut bytes.Buffer
	err := run(
		[]string{"-mode", "encrypt", "-passphrase-env", "SERVERKEY_TEST_PASSPHRASE"},
		bytes.NewReader([]byte(base64.RawStdEncoding.EncodeToString(privateKey))),
		&encryptedOut,
	)
	if err != nil {
		t.Fatal(err)
	}
	var encrypted map[string]any
	if err := json.Unmarshal(encryptedOut.Bytes(), &encrypted); err != nil {
		t.Fatal(err)
	}
	decrypted, err := serverkey.DecryptPrivateKey(encrypted, []byte("old passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Fatalf("encrypted private key mismatch")
	}

	t.Setenv("SERVERKEY_TEST_NEW_PASSPHRASE", "new passphrase")
	var reencryptedOut bytes.Buffer
	err = run(
		[]string{"-mode", "reencrypt", "-old-passphrase-env", "SERVERKEY_TEST_PASSPHRASE", "-new-passphrase-env", "SERVERKEY_TEST_NEW_PASSPHRASE"},
		bytes.NewReader(encryptedOut.Bytes()),
		&reencryptedOut,
	)
	if err != nil {
		t.Fatal(err)
	}
	var reencrypted map[string]any
	if err := json.Unmarshal(reencryptedOut.Bytes(), &reencrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := serverkey.DecryptPrivateKey(reencrypted, []byte("old passphrase")); err == nil {
		t.Fatalf("expected old passphrase to fail")
	}
	decrypted, err = serverkey.DecryptPrivateKey(reencrypted, []byte("new passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, privateKey) {
		t.Fatalf("reencrypted private key mismatch")
	}
}

func TestRunRejectsInvalidModeAndInput(t *testing.T) {
	if err := run(nil, bytes.NewReader(nil), ioDiscard{}); err == nil {
		t.Fatalf("expected missing mode to fail")
	}
	t.Setenv("SERVERKEY_TEST_PASSPHRASE", "passphrase")
	if err := run([]string{"-mode", "encrypt", "-passphrase-env", "SERVERKEY_TEST_PASSPHRASE"}, bytes.NewReader([]byte("not base64!")), ioDiscard{}); err == nil {
		t.Fatalf("expected bad plaintext input to fail")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) {
	return len(p), nil
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
