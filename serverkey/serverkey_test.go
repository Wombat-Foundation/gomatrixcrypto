package serverkey

import (
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"gomatrixlib/fndsa512"
	"gomatrixlib/keyid"
	"gomatrixlib/matrixjson"

	"golang.org/x/crypto/sha3"
)

func testRNG(seed string) io.Reader {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte(seed))
	return h
}

func TestNewSignedFNDSAAndVerify(t *testing.T) {
	priv, pub, err := fndsa512.GenerateKey(testRNG("serverkey-keygen"))
	if err != nil {
		t.Fatal(err)
	}

	metadata := FNDSAMetadata{
		FIPS206Revision: DefaultFIPSRevision,
		Claims:          []string{"constant-time-keygen", "constant-time-signing"},
	}
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-sign"), "example.com", priv, pub, 1798848000000, metadata)
	if err != nil {
		t.Fatal(err)
	}

	wantKeyName := FNDSAAlgorithm + ":" + keyid.ShortID(pub)
	if keyName != wantKeyName {
		t.Fatalf("key name mismatch: got %s want %s", keyName, wantKeyName)
	}
	if got, err := VerifyFNDSASelfSignature(obj, "example.com"); err != nil || got != keyName {
		t.Fatalf("self-signature verify failed: key=%s err=%v", got, err)
	}

	verifyKeys := obj["verify_keys"].(map[string]any)
	keyObject := verifyKeys[keyName].(map[string]any)
	if got := keyObject["key"]; got != base64.RawStdEncoding.EncodeToString(pub) {
		t.Fatalf("public key encoding mismatch")
	}
	if got := keyObject["fips_206_revision"]; got != DefaultFIPSRevision {
		t.Fatalf("fips revision mismatch: got %v", got)
	}
}

func TestVerifyFNDSASelfSignatureRejectsTampering(t *testing.T) {
	priv, pub, err := fndsa512.GenerateKey(testRNG("serverkey-tamper-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	obj, _, err := NewSignedFNDSA(testRNG("serverkey-tamper-sign"), "example.com", priv, pub, 1798848000000, FNDSAMetadata{})
	if err != nil {
		t.Fatal(err)
	}

	obj["server_name"] = "evil.example"
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureRejectsWrongShortID(t *testing.T) {
	priv, pub, err := fndsa512.GenerateKey(testRNG("serverkey-shortid-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-shortid-sign"), "example.com", priv, pub, 1798848000000, FNDSAMetadata{})
	if err != nil {
		t.Fatal(err)
	}

	verifyKeys := obj["verify_keys"].(map[string]any)
	verifyKeys[FNDSAAlgorithm+":AAAAAAAAAAAAAAAA"] = verifyKeys[keyName]
	delete(verifyKeys, keyName)
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidKeyName) {
		t.Fatalf("expected invalid key name, got %v", err)
	}
}

func TestSigningBytesIgnoreSignaturesAndUnsigned(t *testing.T) {
	obj := map[string]any{
		"server_name": "example.com",
		"unsigned":    map[string]any{"ignored": true},
		"signatures":  map[string]any{"ignored": true},
	}
	got, err := SigningBytes(obj)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"server_name":"example.com"}`
	if string(got) != want {
		t.Fatalf("signing bytes mismatch: got %s want %s", got, want)
	}
}

func TestKeyMetadataAndKeyIDDigests(t *testing.T) {
	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-digest-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	keyObject := FNDSAKeyObject(pub, FNDSAMetadata{FIPS206Revision: DefaultFIPSRevision})

	metadataDigest, err := KeyMetadataSHA256(keyObject)
	if err != nil {
		t.Fatal(err)
	}
	if metadataDigest == "" {
		t.Fatalf("empty metadata digest")
	}

	keyID := KeyIDSHA256(pub)
	if len(keyID) != 43 {
		t.Fatalf("unexpected base64url sha256 length: got %d", len(keyID))
	}
}

func TestNewUnsignedFNDSARejectsInvalidInputs(t *testing.T) {
	if _, _, err := NewUnsignedFNDSA("", make([]byte, fndsa512.PublicKeySize), 1, FNDSAMetadata{}); !errors.Is(err, ErrInvalidServerName) {
		t.Fatalf("expected invalid server name, got %v", err)
	}
	if _, _, err := NewUnsignedFNDSA("example.com", []byte("short"), 1, FNDSAMetadata{}); !errors.Is(err, fndsa512.ErrInvalidPublicKey) {
		t.Fatalf("expected invalid public key, got %v", err)
	}
}

func TestNewSignedFNDSARejectsInvalidInputs(t *testing.T) {
	if _, _, err := NewSignedFNDSA(nil, "", []byte("short"), []byte("short"), 1, FNDSAMetadata{}); !errors.Is(err, ErrInvalidServerName) {
		t.Fatalf("expected invalid server name, got %v", err)
	}

	_, pub, err := fndsa512.GenerateKey(testRNG("serverkey-invalid-sign-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewSignedFNDSA(nil, "example.com", []byte("short"), pub, 1, FNDSAMetadata{}); !errors.Is(err, fndsa512.ErrInvalidPrivateKey) {
		t.Fatalf("expected invalid private key, got %v", err)
	}
}

func TestSignFNDSARejectsInvalidInputs(t *testing.T) {
	obj := map[string]any{"server_name": "example.com"}
	if err := SignFNDSA(nil, obj, "", FNDSAAlgorithm+":abc", []byte("short")); !errors.Is(err, ErrInvalidServerName) {
		t.Fatalf("expected invalid server name, got %v", err)
	}
	if err := SignFNDSA(nil, obj, "example.com", "ed25519:auto", []byte("short")); !errors.Is(err, ErrInvalidKeyName) {
		t.Fatalf("expected invalid key name, got %v", err)
	}
	obj["signatures"] = "bad"
	if err := SignFNDSA(nil, obj, "example.com", FNDSAAlgorithm+":abc", []byte("short")); !errors.Is(err, fndsa512.ErrInvalidPrivateKey) {
		t.Fatalf("expected private key validation before signature map mutation, got %v", err)
	}
}

func TestSignFNDSARejectsMalformedExistingSignatures(t *testing.T) {
	priv, pub, err := fndsa512.GenerateKey(testRNG("serverkey-malformed-sigs-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	obj, keyName, err := NewUnsignedFNDSA("example.com", pub, 1, FNDSAMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	obj["signatures"] = "bad"
	if err := SignFNDSA(testRNG("serverkey-malformed-sigs-sign"), obj, "example.com", keyName, priv); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureRejectsMalformedObjects(t *testing.T) {
	if _, err := VerifyFNDSASelfSignature(map[string]any{}, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
	if _, err := VerifyFNDSASelfSignature(map[string]any{
		"verify_keys": map[string]any{},
	}, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
	if _, err := VerifyFNDSASelfSignature(map[string]any{
		"verify_keys": map[string]any{},
		"signatures":  map[string]any{},
	}, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
	if _, err := VerifyFNDSASelfSignature(map[string]any{
		"verify_keys": map[string]any{"ed25519:auto": map[string]any{}},
		"signatures":  map[string]any{"example.com": map[string]any{}},
	}, "example.com"); !errors.Is(err, ErrInvalidKeyName) {
		t.Fatalf("expected invalid key name, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureRejectsBadKeyAndSignatureEncoding(t *testing.T) {
	obj := map[string]any{
		"server_name": "example.com",
		"verify_keys": map[string]any{
			FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": map[string]any{"key": "not base64!"},
		},
		"signatures": map[string]any{"example.com": map[string]any{}},
	}
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); err == nil {
		t.Fatalf("expected bad public key encoding to fail")
	}

	obj["verify_keys"] = map[string]any{
		FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": map[string]any{"key": base64.RawStdEncoding.EncodeToString([]byte("short"))},
	}
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, fndsa512.ErrInvalidPublicKey) {
		t.Fatalf("expected invalid public key, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureRejectsMissingAndBadSignature(t *testing.T) {
	priv, pub, err := fndsa512.GenerateKey(testRNG("serverkey-badsig-keygen"))
	if err != nil {
		t.Fatal(err)
	}
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-badsig-sign"), "example.com", priv, pub, 1, FNDSAMetadata{})
	if err != nil {
		t.Fatal(err)
	}

	serverSigs := obj["signatures"].(map[string]any)["example.com"].(map[string]any)
	delete(serverSigs, keyName)
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected missing signature error, got %v", err)
	}

	serverSigs[keyName] = "not base64!"
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); err == nil {
		t.Fatalf("expected bad signature encoding to fail")
	}
}

func TestKeyMetadataSHA256RejectsUnsupportedObject(t *testing.T) {
	if _, err := KeyMetadataSHA256(map[string]any{"bad": 1.5}); !errors.Is(err, matrixjson.ErrUnsupportedType) {
		t.Fatalf("expected unsupported metadata object, got %v", err)
	}
}
