package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"gomatrixlib/serverkey"
)

func main() {
	mode := flag.String("mode", "", "operation: encrypt or reencrypt")
	in := flag.String("in", "-", "input file, or - for stdin")
	passphraseEnv := flag.String("passphrase-env", "", "environment variable containing the passphrase for encrypt")
	passphraseFile := flag.String("passphrase-file", "", "file containing the passphrase for encrypt")
	oldPassphraseEnv := flag.String("old-passphrase-env", "", "environment variable containing the old passphrase for reencrypt")
	oldPassphraseFile := flag.String("old-passphrase-file", "", "file containing the old passphrase for reencrypt")
	newPassphraseEnv := flag.String("new-passphrase-env", "", "environment variable containing the new passphrase for reencrypt")
	newPassphraseFile := flag.String("new-passphrase-file", "", "file containing the new passphrase for reencrypt")
	flag.Parse()

	input, err := readInput(*in)
	if err != nil {
		fatal(err)
	}

	var encrypted map[string]any
	switch *mode {
	case "encrypt":
		passphrase, err := readPassphrase(*passphraseEnv, *passphraseFile, "passphrase")
		if err != nil {
			fatal(err)
		}
		privateKey, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(input)))
		if err != nil {
			fatal(err)
		}
		encrypted, err = serverkey.EncryptPrivateKey(nil, privateKey, passphrase, serverkey.DefaultPrivateKeyEncryptionParams())
		if err != nil {
			fatal(err)
		}
	case "reencrypt":
		oldPassphrase, err := readPassphrase(*oldPassphraseEnv, *oldPassphraseFile, "old passphrase")
		if err != nil {
			fatal(err)
		}
		newPassphrase, err := readPassphrase(*newPassphraseEnv, *newPassphraseFile, "new passphrase")
		if err != nil {
			fatal(err)
		}
		var oldEncrypted map[string]any
		if err := json.Unmarshal(input, &oldEncrypted); err != nil {
			fatal(err)
		}
		encrypted, err = serverkey.ReencryptPrivateKey(nil, oldEncrypted, oldPassphrase, newPassphrase, serverkey.DefaultPrivateKeyEncryptionParams())
		if err != nil {
			fatal(err)
		}
	default:
		fatal(fmt.Errorf("set -mode to encrypt or reencrypt"))
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(encrypted); err != nil {
		fatal(err)
	}
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func readPassphrase(envName, fileName, label string) ([]byte, error) {
	if envName != "" && fileName != "" {
		return nil, fmt.Errorf("use only one of -%s-env or -%s-file", strings.ReplaceAll(label, " ", "-"), strings.ReplaceAll(label, " ", "-"))
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
	return nil, fmt.Errorf("missing %s source", label)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "serverkey-keytool: %v\n", err)
	os.Exit(1)
}
