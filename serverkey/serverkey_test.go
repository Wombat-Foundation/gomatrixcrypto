package serverkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo"
	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"

	"golang.org/x/crypto/sha3"
)

func testRNG(seed string) io.Reader {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte(seed))
	return h
}

var testMintingProofs sync.Map

func testMintingProof(t *testing.T, serverName string, pub []byte) FNDSAMintingProof {
	t.Helper()
	cacheKey := serverName + "\x00" + string(pub)
	if cached, ok := testMintingProofs.Load(cacheKey); ok {
		proof := cached.(FNDSAMintingProof)
		proof.Solution = append([]uint32(nil), proof.Solution...)
		return proof
	}
	cfg := cuckoo.Config{EdgeBits: 8, ProofSize: 4}
	for nonce := uint32(0); nonce < 64; nonce++ {
		seed, err := GraphSeed(pub, serverName, "test.cuckoo-cycle-4-8-sha3-256-cogen", uint32(nonce))
		if err != nil {
			t.Fatal(err)
		}
		proof, err := cuckoo.FindProof(cfg, seed[:], 1<<12)
		if err == cuckoo.ErrNoSolution {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result := FNDSAMintingProof{
			Algorithm: "test.cuckoo-cycle-4-8-sha3-256-cogen",
			Nonce:     nonce,
			Solution:  append([]uint32(nil), proof...),
		}
		testMintingProofs.Store(cacheKey, result)
		result.Solution = append([]uint32(nil), result.Solution...)
		return result
	}
	t.Fatal("no test minting proof found")
	return FNDSAMintingProof{}
}

func testRegisteredMintingProof(t *testing.T, serverName string, pub []byte) (string, FNDSAMintingProof) {
	t.Helper()
	const profileName = "test.serverkey.profile"
	profiles[profileName] = profile{
		config:     cuckoo.Config{EdgeBits: 12, ProofSize: 4},
		graphTag:   "test.serverkey.graph",
		keyIDTag:   "test.serverkey.keyid",
		shortBytes: 16,
	}
	t.Cleanup(func() { delete(profiles, profileName) })

	for nonce := uint32(0); nonce < 256; nonce++ {
		seed, err := GraphSeed(pub, serverName, profileName, nonce)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := cuckoo.FindProof(profiles[profileName].config, seed[:], 1<<12)
		if errors.Is(err, cuckoo.ErrNoSolution) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		return profileName, FNDSAMintingProof{Algorithm: profileName, Nonce: nonce, Solution: proof}
	}
	t.Fatal("no registered test minting proof found")
	return "", FNDSAMintingProof{}
}

func TestNewSignedFNDSAAndVerify(t *testing.T) {
	priv, pub := testKeyPair(t, 0)

	proof := testMintingProof(t, "example.com", pub)
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-sign"), "example.com", priv, pub, 1798848000000, FNDSAMetadata{}, proof)
	if err != nil {
		t.Fatal(err)
	}

	keyID, err := KeyID(pub, "example.com", proof)
	if err != nil {
		t.Fatal(err)
	}
	wantKeyName := FNDSAAlgorithm + ":" + ShortKeyID(keyID)
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
	if _, ok := keyObject["pow"].(map[string]any); !ok {
		t.Fatalf("missing pow object")
	}
	if _, ok := obj["old_verify_keys"]; ok {
		t.Fatalf("empty optional old_verify_keys must be omitted")
	}
}

func TestVerifyFNDSASelfSignatureRejectsTampering(t *testing.T) {
	priv, pub := testKeyPair(t, 0)
	proof := testMintingProof(t, "example.com", pub)
	obj, _, err := NewSignedFNDSA(testRNG("serverkey-sign"), "example.com", priv, pub, 1798848000000, FNDSAMetadata{}, proof)
	if err != nil {
		t.Fatal(err)
	}

	obj["server_name"] = "evil.example"
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureDoesNotClaimProtocolValidation(t *testing.T) {
	priv, pub := testKeyPair(t, 0)
	proof := testMintingProof(t, "example.com", pub)
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-sign"), "example.com", priv, pub, 1798848000000, FNDSAMetadata{}, proof)
	if err != nil {
		t.Fatal(err)
	}

	if got, err := VerifyFNDSASelfSignature(obj, "example.com"); err != nil || got != keyName {
		t.Fatalf("signature-only verification failed: key=%s err=%v", got, err)
	}
}

func TestVerifyMintedFNDSAServerKeyBindsProfileProofAndKeyName(t *testing.T) {
	priv, pub := testKeyPair(t, 0)
	_, proof := testRegisteredMintingProof(t, "example.com", pub)
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-minted-sign"), "example.com", priv, pub, 1, FNDSAMetadata{}, proof)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := VerifyMintedFNDSAServerKey(obj, "example.com"); err != nil || got != keyName {
		t.Fatalf("minted-key verification failed: key=%s err=%v", got, err)
	}

	verifyKeys := obj["verify_keys"].(map[string]any)
	keyObject := verifyKeys[keyName].(map[string]any)
	keyObject["profile"] = "unknown.profile"
	if _, err := VerifyMintedFNDSAServerKey(obj, "example.com"); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected unknown-profile rejection, got %v", err)
	}
	keyObject["profile"] = proof.Algorithm

	delete(verifyKeys, keyName)
	badKeyName := FNDSAAlgorithm + ":00000000000000000000000000000000"
	verifyKeys[badKeyName] = keyObject
	serverSigs := obj["signatures"].(map[string]any)["example.com"].(map[string]any)
	serverSigs[badKeyName] = serverSigs[keyName]
	delete(serverSigs, keyName)
	if _, err := VerifyMintedFNDSAServerKey(obj, "example.com"); !errors.Is(err, ErrInvalidKeyName) {
		t.Fatalf("expected key-name rejection, got %v", err)
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
	_, pub := testKeyPair(t, 1)
	proof := testMintingProof(t, "example.com", pub)
	keyObject := FNDSAKeyObject(pub, FNDSAMetadata{FIPS206Revision: DefaultFIPSRevision}, proof)

	metadataDigest, err := KeyMetadataSHA256(keyObject)
	if err != nil {
		t.Fatal(err)
	}
	if metadataDigest == "" {
		t.Fatalf("empty metadata digest")
	}

	keyID, err := KeyIDBase64(pub, "example.com", proof)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyID) != 43 {
		t.Fatalf("unexpected base64url key id length: got %d", len(keyID))
	}

	archivedKeyID := KeyIDSHA256(pub)
	if len(archivedKeyID) != 43 {
		t.Fatalf("unexpected archived key id length: got %d", len(archivedKeyID))
	}
}

func TestNewUnsignedFNDSARejectsInvalidInputs(t *testing.T) {
	if _, _, err := NewUnsignedFNDSA("", make([]byte, fndsa512.PublicKeySize), 1, FNDSAMetadata{}, FNDSAMintingProof{}); !errors.Is(err, ErrInvalidServerName) {
		t.Fatalf("expected invalid server name, got %v", err)
	}
	if _, _, err := NewUnsignedFNDSA("example.com", []byte("short"), 1, FNDSAMetadata{}, FNDSAMintingProof{}); !errors.Is(err, fndsa512.ErrInvalidPublicKey) {
		t.Fatalf("expected invalid public key, got %v", err)
	}
	if _, _, err := NewUnsignedFNDSA(string([]byte{0xff}), make([]byte, fndsa512.PublicKeySize), 1, FNDSAMetadata{}, FNDSAMintingProof{}); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected canonical JSON error, got %v", err)
	}
}

func TestNewSignedFNDSARejectsInvalidInputs(t *testing.T) {
	if _, _, err := NewSignedFNDSA(nil, "", []byte("short"), []byte("short"), 1, FNDSAMetadata{}, FNDSAMintingProof{}); !errors.Is(err, ErrInvalidServerName) {
		t.Fatalf("expected invalid server name, got %v", err)
	}

	_, pub := testKeyPair(t, 0)
	proof := testMintingProof(t, "example.com", pub)
	if _, _, err := NewSignedFNDSA(nil, "example.com", []byte("short"), pub, 1, FNDSAMetadata{}, proof); !errors.Is(err, fndsa512.ErrInvalidPrivateKey) {
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
	priv, pub := testKeyPair(t, 0)
	proof := testMintingProof(t, "example.com", pub)
	obj, keyName, err := NewUnsignedFNDSA("example.com", pub, 1, FNDSAMetadata{}, proof)
	if err != nil {
		t.Fatal(err)
	}
	obj["signatures"] = "bad"
	if err := SignFNDSA(testRNG("serverkey-sign"), obj, "example.com", keyName, priv); !errors.Is(err, ErrInvalidKeyObject) {
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
	priv, pub := testKeyPair(t, 0)
	proof := testMintingProof(t, "example.com", pub)
	obj, keyName, err := NewSignedFNDSA(testRNG("serverkey-badsig-sign"), "example.com", priv, pub, 1, FNDSAMetadata{}, proof)
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

func TestEncryptPrivateKeyRoundTrip(t *testing.T) {
	priv, _ := testKeyPair(t, 0)
	defaultParams := DefaultPrivateKeyEncryptionParams()
	if defaultParams.Time == 0 || defaultParams.MemoryKiB == 0 || defaultParams.Threads == 0 {
		t.Fatalf("invalid default encryption params: %#v", defaultParams)
	}
	params := PrivateKeyEncryptionParams{
		Time:      1,
		MemoryKiB: 8 * 1024,
		Threads:   1,
		Salt:      bytes.Repeat([]byte{0x11}, privateKeySaltSize),
		Nonce:     bytes.Repeat([]byte{0x22}, 24),
	}
	encrypted, err := EncryptPrivateKey(nil, priv, []byte("correct horse battery staple"), params)
	if err != nil {
		t.Fatal(err)
	}
	if got := encrypted["algorithm"]; got != EncryptedPrivateKeyAlgorithm {
		t.Fatalf("algorithm mismatch: got %v", got)
	}

	decrypted, err := DecryptPrivateKey(encrypted, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, priv) {
		t.Fatalf("private key round trip mismatch")
	}
	if _, err := DecryptPrivateKey(encrypted, []byte("wrong passphrase")); err == nil {
		t.Fatalf("expected wrong passphrase to fail")
	}
}

func TestReencryptPrivateKeyChangesPassphrase(t *testing.T) {
	priv, _ := testKeyPair(t, 0)
	oldParams := PrivateKeyEncryptionParams{
		Time:      1,
		MemoryKiB: 8 * 1024,
		Threads:   1,
		Salt:      bytes.Repeat([]byte{0x33}, privateKeySaltSize),
		Nonce:     bytes.Repeat([]byte{0x44}, 24),
	}
	encrypted, err := EncryptPrivateKey(nil, priv, []byte("old horse battery staple"), oldParams)
	if err != nil {
		t.Fatal(err)
	}
	newParams := PrivateKeyEncryptionParams{
		Time:      1,
		MemoryKiB: 8 * 1024,
		Threads:   1,
		Salt:      bytes.Repeat([]byte{0x55}, privateKeySaltSize),
		Nonce:     bytes.Repeat([]byte{0x66}, 24),
	}
	reencrypted, err := ReencryptPrivateKey(nil, encrypted, []byte("old horse battery staple"), []byte("new horse battery staple"), newParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptPrivateKey(reencrypted, []byte("old horse battery staple")); err == nil {
		t.Fatalf("expected old passphrase to fail")
	}
	decrypted, err := DecryptPrivateKey(reencrypted, []byte("new horse battery staple"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decrypted, priv) {
		t.Fatalf("private key mismatch after reencrypt")
	}
}

func TestEncryptPrivateKeyRejectsInvalidInputs(t *testing.T) {
	params := PrivateKeyEncryptionParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	if _, err := EncryptPrivateKey(nil, []byte("short"), []byte("correct horse battery staple"), params); !errors.Is(err, fndsa512.ErrInvalidPrivateKey) {
		t.Fatalf("expected invalid private key, got %v", err)
	}
	if _, err := EncryptPrivateKey(nil, make([]byte, fndsa512.PrivateKeySize), nil, params); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("expected invalid passphrase, got %v", err)
	}
	if _, err := EncryptPrivateKey(nil, make([]byte, fndsa512.PrivateKeySize), []byte("correct horse battery staple"), PrivateKeyEncryptionParams{}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid params, got %v", err)
	}
}

func TestEncryptPrivateKeyRejectsShortPassphrase(t *testing.T) {
	params := PrivateKeyEncryptionParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
	if _, err := EncryptPrivateKey(nil, make([]byte, fndsa512.PrivateKeySize), []byte("too short"), params); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("expected weak passphrase, got %v", err)
	}
}

func TestDecryptPrivateKeyRejectsMalformedObjects(t *testing.T) {
	if _, err := DecryptPrivateKey(map[string]any{}, []byte("passphrase")); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid algorithm, got %v", err)
	}
	valid := map[string]any{
		"algorithm": EncryptedPrivateKeyAlgorithm,
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(1),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, privateKeySaltSize)),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0x88}, 24)),
		},
		"ciphertext": base64.RawStdEncoding.EncodeToString([]byte("bad ciphertext")),
	}
	cases := []struct {
		name string
		edit func(map[string]any)
	}{
		{
			name: "missing kdf",
			edit: func(encrypted map[string]any) {
				delete(encrypted, "kdf")
			},
		},
		{
			name: "bad kdf algorithm",
			edit: func(encrypted map[string]any) {
				encrypted["kdf"].(map[string]any)["algorithm"] = "other"
			},
		},
		{
			name: "bad salt",
			edit: func(encrypted map[string]any) {
				encrypted["kdf"].(map[string]any)["salt"] = "not base64!"
			},
		},
		{
			name: "missing aead",
			edit: func(encrypted map[string]any) {
				delete(encrypted, "aead")
			},
		},
		{
			name: "bad aead algorithm",
			edit: func(encrypted map[string]any) {
				encrypted["aead"].(map[string]any)["algorithm"] = "other"
			},
		},
		{
			name: "bad nonce",
			edit: func(encrypted map[string]any) {
				encrypted["aead"].(map[string]any)["nonce"] = "not base64!"
			},
		},
		{
			name: "missing ciphertext",
			edit: func(encrypted map[string]any) {
				delete(encrypted, "ciphertext")
			},
		},
		{
			name: "bad ciphertext",
			edit: func(encrypted map[string]any) {
				encrypted["ciphertext"] = "not base64!"
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted := cloneMap(valid)
			tc.edit(encrypted)
			if _, err := DecryptPrivateKey(encrypted, []byte("passphrase")); err == nil {
				t.Fatalf("expected malformed encrypted key to fail")
			}
		})
	}
	if _, err := DecryptPrivateKey(valid, []byte("passphrase")); err == nil {
		t.Fatalf("expected authentication failure for malformed ciphertext")
	}
}

func TestMintingProofFromObjectRejectsMalformedProofs(t *testing.T) {
	cases := []map[string]any{
		{},
		{"profile": "", "pow": map[string]any{"nonce": uint64(0), "solution": []any{uint64(1)}}},
		{"profile": "test", "pow": map[string]any{"nonce": int64(-1), "solution": []any{uint64(1)}}},
		{"profile": "test", "pow": map[string]any{"nonce": uint64(0), "solution": "bad"}},
		{"profile": "test", "pow": map[string]any{"nonce": uint64(0), "solution": []any{uint64(^uint32(0)) + 1}}},
	}
	for i, keyObject := range cases {
		if _, _, err := mintingProofFromObject(keyObject); err == nil {
			t.Fatalf("case %d: expected invalid proof to fail", i)
		}
	}
}

func TestUint64FromAnyAcceptedTypes(t *testing.T) {
	cases := []any{
		uint8(7),
		uint16(7),
		uint32(7),
		uint64(7),
		uint(7),
		int(7),
		int64(7),
		float64(7),
	}
	for _, value := range cases {
		got, err := uint64FromAny(value)
		if err != nil {
			t.Fatalf("uint64FromAny(%T) failed: %v", value, err)
		}
		if got != 7 {
			t.Fatalf("uint64FromAny(%T) = %d, want 7", value, got)
		}
	}
}

func TestUint64FromAnyRejectsInvalidValues(t *testing.T) {
	cases := []any{
		int(-1),
		int64(-1),
		float64(-1),
		float64(1.5),
		"7",
	}
	for _, value := range cases {
		if _, err := uint64FromAny(value); !errors.Is(err, ErrInvalidKeyObject) {
			t.Fatalf("uint64FromAny(%T) error = %v, want ErrInvalidKeyObject", value, err)
		}
	}
}

func cloneMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		if nested, ok := value.(map[string]any); ok {
			out[key] = cloneMap(nested)
			continue
		}
		out[key] = value
	}
	return out
}
