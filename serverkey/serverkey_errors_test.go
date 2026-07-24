package serverkey

import (
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"
)

func TestGraphSeedPropagatesCanonicalError(t *testing.T) {
	pub := make([]byte, fndsa512.PublicKeySize)
	if _, err := GraphSeed(pub, string([]byte{0xff}), ProductionProfile, 0); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}

func TestUint32FromAnyRejectsOversizeNonce(t *testing.T) {
	if _, err := uint32FromAny(uint64(^uint32(0)) + 1); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected oversized nonce rejection, got %v", err)
	}
}

// TestShortKeyIDRejectsUnknownProfile requires exact profile registration.
func TestShortKeyIDRejectsUnknownProfile(t *testing.T) {
	if _, err := ShortKeyID("unknown.profile", [32]byte{}); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected unknown profile rejection, got %v", err)
	}
}

// TestNewUnsignedFNDSARejectsUnknownProfile rejects unregistered profiles.
func TestNewUnsignedFNDSARejectsUnknownProfile(t *testing.T) {
	if _, _, err := NewUnsignedFNDSA("example.com", make([]byte, fndsa512.PublicKeySize), 1, FNDSAMetadata{}, FNDSAMintingProof{Algorithm: "unknown.profile"}); !errors.Is(err, ErrUnknownProfile) {
		t.Fatalf("expected unknown profile error, got %v", err)
	}
}

// TestGraphSeedAllowsUnknownProfileForDerivation keeps derivation separate from dispatch.
func TestGraphSeedAllowsUnknownProfileForDerivation(t *testing.T) {
	if _, err := GraphSeed(make([]byte, fndsa512.PublicKeySize), "example.com", "unknown.profile", 0); err != nil {
		t.Fatalf("unknown profile derivation failed: %v", err)
	}
}

// TestValidateProofPropagatesGraphSeedError preserves canonicalization failures.
func TestValidateProofPropagatesGraphSeedError(t *testing.T) {
	if err := validateProof(make([]byte, fndsa512.PublicKeySize), string([]byte{0xff}), ProductionProfile, FNDSAMintingProof{}); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected canonical error, got %v", err)
	}
}

func TestKeyIDBase64PropagatesCanonicalError(t *testing.T) {
	if _, err := KeyIDBase64(make([]byte, fndsa512.PublicKeySize), string([]byte{0xff}), FNDSAMintingProof{}); !errors.Is(err, matrixjson.ErrInvalidString) {
		t.Fatalf("expected invalid string error, got %v", err)
	}
}

func TestSignFNDSAPropagatesSigningBytesError(t *testing.T) {
	obj := map[string]any{"server_name": "example.com", "bad": 1.5}
	if err := SignFNDSA(nil, obj, "example.com", FNDSAAlgorithm+":abc", []byte("short")); !errors.Is(err, matrixjson.ErrUnsupportedType) {
		t.Fatalf("expected unsupported type error, got %v", err)
	}
}

func TestSignFNDSAAddsSecondKeyForExistingServer(t *testing.T) {
	priv1, pub1 := testKeyPair(t, 0)
	priv2, pub2 := testKeyPair(t, 1)
	proof1 := testMintingProof(t, "example.com", pub1)
	proof2 := testMintingProof(t, "example.com", pub2)

	obj, keyName1, err := NewSignedFNDSA(testRNG("serverkey-sign"), "example.com", priv1, pub1, 1, FNDSAMetadata{}, proof1)
	if err != nil {
		t.Fatal(err)
	}
	keyID2, err := KeyID(pub2, "example.com", proof2)
	if err != nil {
		t.Fatal(err)
	}
	shortKeyID, err := ShortKeyID(proof2.Algorithm, keyID2)
	if err != nil {
		t.Fatal(err)
	}
	keyName2 := FNDSAAlgorithm + ":" + shortKeyID
	if err := SignFNDSA(testRNG("serverkey-sign"), obj, "example.com", keyName2, priv2); err != nil {
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
		"server_name": "example.com",
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
	if _, err := VerifyMintedFNDSAServerKey(obj, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object, got %v", err)
	}
}

func TestVerifyFNDSASelfSignaturePropagatesMintingProofError(t *testing.T) {
	obj := map[string]any{
		"server_name": "example.com",
		"verify_keys": map[string]any{
			FNDSAAlgorithm + ":AAAAAAAAAAAAAAAA": map[string]any{
				"key": base64.RawStdEncoding.EncodeToString(make([]byte, fndsa512.PublicKeySize)),
			},
		},
		"signatures": map[string]any{"example.com": map[string]any{}},
	}
	if _, err := VerifyMintedFNDSAServerKey(obj, "example.com"); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for missing pow, got %v", err)
	}
}

func TestMintingProofFromObjectRejectsMissingPow(t *testing.T) {
	if _, _, err := mintingProofFromObject(map[string]any{"profile": ProductionProfile}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected missing-pow rejection, got %v", err)
	}
}

func TestVerifyFNDSASelfSignaturePropagatesKeyIDError(t *testing.T) {
	// The invalid-UTF-8 server name must NOT appear anywhere inside obj, or
	// SigningBytes would fail first (verify_keys isn't excluded from the
	// signing bytes, so any malformed value embedded there trips line
	// 246-249 before the loop ever reaches KeyID). Passing it only as the
	// serverName argument means it reaches matrixjson.Canonical solely via
	// mintingObject's "server_name" field inside KeyID.
	serverName := string([]byte{0xff})
	obj := map[string]any{
		"server_name": serverName,
		"verify_keys": map[string]any{
			FNDSAAlgorithm + ":AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA": map[string]any{
				"key":     base64.RawStdEncoding.EncodeToString(make([]byte, fndsa512.PublicKeySize)),
				"profile": ProductionProfile,
				"pow": map[string]any{
					"nonce":    uint64(0),
					"solution": []any{uint64(1)},
				},
			},
		},
		"signatures": map[string]any{serverName: map[string]any{}},
	}
	if _, err := VerifyMintedFNDSAServerKey(obj, serverName); !errors.Is(err, matrixjson.ErrInvalidString) {
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
