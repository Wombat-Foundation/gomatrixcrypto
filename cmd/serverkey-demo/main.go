package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"gomatrixlib/fndsa512"
	"gomatrixlib/keyid"
	"gomatrixlib/serverkey"
)

func main() {
	serverName := flag.String("server", "example.com", "Matrix server_name to bind into the self-signed key object")
	validDays := flag.Int("valid-days", 7, "validity window in days")
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

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")

	fmt.Printf("server_name: %s\n", *serverName)
	fmt.Printf("key_name: %s\n", keyName)
	fmt.Printf("short_id: %s\n", keyid.ShortID(pub))
	fmt.Printf("key_id_sha256: %s\n", serverkey.KeyIDSHA256(pub))
	fmt.Printf("key_metadata_sha256: %s\n", metadataDigest)
	fmt.Printf("private_key_base64: %s\n", base64.RawStdEncoding.EncodeToString(priv))
	fmt.Println("server_key_object:")
	if err := enc.Encode(obj); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
