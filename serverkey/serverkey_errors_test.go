package serverkey

import (
	"encoding/base64"
	"errors"
	"testing"

	"gomatrixlib/fndsa512"
	"gomatrixlib/matrixjson"
)

// hugeNonceProof is a syntactically valid proof whose Nonce exceeds
// matrixjson's canonical-integer range, forcing KeyID's Canonical call to
// fail. This is the only realistic way to make KeyID/GraphSeed's canonical
// encoding step return an error, since every other field is a bounded
// string or uint32.
func hugeNonceProof() FNDSAMintingProof {
	return FNDSAMintingProof{Algorithm: "test", Nonce: 1 << 63, Solution: []uint32{1, 2}}
}

func TestNewUnsignedFNDSAPropagatesKeyIDError(t *testing.T) {
	pub := make([]byte, fndsa512.PublicKeySize)
	if _, _, err := NewUnsignedFNDSA("example.com", pub, 1, FNDSAMetadata{}, hugeNonceProof()); !errors.Is(err, matrixjson.ErrIntegerRange) {
		t.Fatalf("expected integer range error, got %v", err)
	}
}

func TestGraphSeedPropagatesCanonicalError(t *testing.T) {
	pub := make([]byte, fndsa512.PublicKeySize)
	if _, err := GraphSeed(pub, string([]byte{0xff}), 0); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}

func TestKeyIDPropagatesCanonicalError(t *testing.T) {
	pub := make([]byte, fndsa512.PublicKeySize)
	if _, err := KeyID(pub, "example.com", hugeNonceProof()); !errors.Is(err, matrixjson.ErrIntegerRange) {
		t.Fatalf("expected integer range error, got %v", err)
	}
}

func TestKeyIDBase64PropagatesKeyIDError(t *testing.T) {
	pub := make([]byte, fndsa512.PublicKeySize)
	if _, err := KeyIDBase64(pub, "example.com", hugeNonceProof()); !errors.Is(err, matrixjson.ErrIntegerRange) {
		t.Fatalf("expected integer range error, got %v", err)
	}
}

func TestSignFNDSAPropagatesSigningBytesError(t *testing.T) {
	obj := map[string]any{"server_name": "example.com", "bad": 1.5}
	if err := SignFNDSA(nil, obj, "example.com", FNDSAAlgorithm+":abc", []byte("short")); !errors.Is(err, matrixjson.ErrUnsupportedType) {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestSignFNDSAAddsSecondKeyForExistingServer(t *testing.T) {
	priv1, pub1, err := fndsa512.GenerateKey(testRNG("serverkey-second-key-1"))
	if err != nil {
		t.Fatal(err)
	}
	priv2, pub2, err := fndsa512.GenerateKey(testRNG("serverkey-second-key-2"))
	if err != nil {
		t.Fatal(err)
	}
	proof1 := testMintingProof(t, "example.com", pub1)
	proof2 := testMintingProof(t, "example.com", pub2)

	obj, keyName1, err := NewSignedFNDSA(testRNG("serverkey-second-key-sign-1"), "example.com", priv1, pub1, 1, FNDSAMetadata{}, proof1)
	if err != nil {
		t.Fatal(err)
	}
	keyID2, err := KeyID(pub2, "example.com", proof2)
	if err != nil {
		t.Fatal(err)
	}
	keyName2 := FNDSAAlgorithm + ":" + ShortKeyID(keyID2)
	if err := SignFNDSA(testRNG("serverkey-second-key-sign-2"), obj, "example.com", keyName2, priv2); err != nil {
		t.Fatal(err)
	}

	signatures, ok := obj["signatures"].(map[string]any)
	if !ok {
		t.Fatalf("expected signatures map, got %T", obj["signatures"])
	}
	serverSigs, ok := signatures["example.com"].(map[string]any)
	if !ok {
		t.Fatalf("expected server signatures map, got %T", signatures["example.com"])
	}
	if _, ok := serverSigs[keyName1]; !ok {
		t.Fatalf("expected first key's signature to be preserved")
	}
	if _, ok := serverSigs[keyName2]; !ok {
		t.Fatalf("expected second key's signature to be added")
	}
}

func TestVerifyFNDSASelfSignaturePropagatesSigningBytesError(t *testing.T) {
	obj := map[string]any{
		"verify_keys": map[string]any{},
		"signatures":  map[string]any{"example.com": map[string]any{}},
		"bad":         1.5,
	}
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, matrixjson.ErrUnsupportedType) {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestVerifyFNDSASelfSignatureRejectsNonMapVerifyKeyEntry(t *testing.T) {
	obj := map[string]any{
		"verify_keys": map[string]any{FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": "not a map"},
		"signatures":  map[string]any{"example.com": map[string]any{}},
	}
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
}

func TestVerifyFNDSASelfSignaturePropagatesMintingProofError(t *testing.T) {
	obj := map[string]any{
		"verify_keys": map[string]any{
			FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": map[string]any{
				"key": base64.RawStdEncoding.EncodeToString(make([]byte, fndsa512.PublicKeySize)),
			},
		},
		"signatures": map[string]any{"example.com": map[string]any{}},
	}
	if _, err := VerifyFNDSASelfSignature(obj, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for missing pow, got %v", err)
	}
}

func TestVerifyFNDSASelfSignaturePropagatesKeyIDError(t *testing.T) {
	// The invalid-UTF-8 server name must NOT appear anywhere inside obj, or
	// SigningBytes would fail first (verify_keys isn't excluded from the
	// signing bytes, so any malformed value embedded there trips line
	// 246-249 before the loop ever reaches KeyID). Passing it only as the
	// serverName argument means it reaches matrixjson.Canonical solely via
	// MintingObject's "server_name" field inside KeyID.
	serverName := string([]byte{0xff})
	obj := map[string]any{
		"verify_keys": map[string]any{
			FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": map[string]any{
				"key": base64.RawStdEncoding.EncodeToString(make([]byte, fndsa512.PublicKeySize)),
				"pow": map[string]any{
					"algorithm": "test",
					"nonce":     uint64(0),
					"solution":  []any{uint64(1)},
				},
			},
		},
		"signatures": map[string]any{serverName: map[string]any{}},
	}
	if _, err := VerifyFNDSASelfSignature(obj, serverName); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}

func TestPublicKeyFromObjectRejectsMissingKey(t *testing.T) {
	if _, err := publicKeyFromObject(map[string]any{}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
}

func TestUint32sFromAnyAcceptsNativeSlice(t *testing.T) {
	got, err := uint32sFromAny([]uint32{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Fatalf("uint32sFromAny native slice mismatch: got %v", got)
	}
}

func TestUint32sFromAnyRejectsInvalidElement(t *testing.T) {
	if _, err := uint32sFromAny([]any{"bad"}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
}
