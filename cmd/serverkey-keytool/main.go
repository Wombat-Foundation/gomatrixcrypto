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
	if err := run(os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fatal(err)
	}
}

func run(args []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("serverkey-keytool", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	mode := flags.String("mode", "", "operation: encrypt or reencrypt")
	in := flags.String("in", "-", "input file, or - for stdin")
	passphraseEnv := flags.String("passphrase-env", "", "environment variable containing the passphrase for encrypt")
	passphraseFile := flags.String("passphrase-file", "", "file containing the passphrase for encrypt")
	oldPassphraseEnv := flags.String("old-passphrase-env", "", "environment variable containing the old passphrase for reencrypt")
	oldPassphraseFile := flags.String("old-passphrase-file", "", "file containing the old passphrase for reencrypt")
	newPassphraseEnv := flags.String("new-passphrase-env", "", "environment variable containing the new passphrase for reencrypt")
	newPassphraseFile := flags.String("new-passphrase-file", "", "file containing the new passphrase for reencrypt")
	if err := flags.Parse(args); err != nil {
		return err
	}

	input, err := readInput(*in, stdin)
	if err != nil {
		return err
	}

	var encrypted map[string]any
	switch *mode {
	case "encrypt":
		passphrase, err := readPassphrase(*passphraseEnv, *passphraseFile, "passphrase")
		if err != nil {
			return err
		}
		privateKey, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(input)))
		if err != nil {
			return err
		}
		encrypted, err = serverkey.EncryptPrivateKey(nil, privateKey, passphrase, serverkey.DefaultPrivateKeyEncryptionParams())
		if err != nil {
			return err
		}
	case "reencrypt":
		oldPassphrase, err := readPassphrase(*oldPassphraseEnv, *oldPassphraseFile, "old passphrase")
		if err != nil {
			return err
		}
		newPassphrase, err := readPassphrase(*newPassphraseEnv, *newPassphraseFile, "new passphrase")
		if err != nil {
			return err
		}
		var oldEncrypted map[string]any
		if err := json.Unmarshal(input, &oldEncrypted); err != nil {
			return err
		}
		encrypted, err = serverkey.ReencryptPrivateKey(nil, oldEncrypted, oldPassphrase, newPassphrase, serverkey.DefaultPrivateKeyEncryptionParams())
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("set -mode to encrypt or reencrypt")
	}

	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(encrypted)
}

func readInput(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
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
