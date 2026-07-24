// Package serverkey builds and verifies Matrix server-key objects.
package serverkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Wombat-Foundation/gomatrixcrypto/cuckoo"
	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/keyid"
	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"

	"golang.org/x/crypto/sha3"
)

const (
	FNDSAAlgorithm      = "fndsa512"
	ProductionProfile   = "tk.nutra.msc45xx.serverkey.v1"
	ProductionPoW       = ProductionProfile
	DefaultFIPSRevision = "ipd-2025-08"
	productionGraphTag  = "tk.nutra.msc45xx.serverkey.v1.graph"
	productionKeyIDTag  = "tk.nutra.msc45xx.serverkey.v1.keyid"
)

var (
	ErrInvalidServerName = errors.New("invalid server name")
	ErrInvalidKeyName    = errors.New("invalid key name")
	ErrInvalidKeyObject  = errors.New("invalid server key object")
	ErrInvalidSignature  = errors.New("invalid server key signature")
	ErrUnknownProfile    = errors.New("unknown server-key profile")
)

type profile struct {
	config     cuckoo.Config
	graphTag   string
	keyIDTag   string
	shortBytes int
}

// FNDSAMetadata is retained for source compatibility. Profile metadata is
// authoritative; callers must not rely on these self-asserted fields.
type FNDSAMetadata struct {
	FIPS206Revision string
	Claims          []string
}

var profiles = map[string]profile{
	ProductionProfile: {
		config:     cuckoo.Config{EdgeBits: 29, ProofSize: 42},
		graphTag:   productionGraphTag,
		keyIDTag:   productionKeyIDTag,
		shortBytes: 16,
	},
}

// FNDSAMintingProof records the proof data bound to a profile-selected graph.
type FNDSAMintingProof struct {
	Algorithm string
	Nonce     uint32
	Solution  []uint32
}

// NewSignedFNDSA builds a Matrix server-key object with one FN-DSA verify key
// and adds the matching self-signature.
func NewSignedFNDSA(rng io.Reader, serverName string, privateKey, publicKey []byte, validUntilTS int64, metadata FNDSAMetadata, proof FNDSAMintingProof) (map[string]any, string, error) {
	obj, keyName, err := NewUnsignedFNDSA(serverName, publicKey, validUntilTS, metadata, proof)
	if err != nil {
		return nil, "", err
	}
	if err := SignFNDSA(rng, obj, serverName, keyName, privateKey); err != nil {
		return nil, "", err
	}
	return obj, keyName, nil
}

// NewUnsignedFNDSA builds the key object before signatures are attached.
func NewUnsignedFNDSA(serverName string, publicKey []byte, validUntilTS int64, _ FNDSAMetadata, proof FNDSAMintingProof) (map[string]any, string, error) {
	if serverName == "" {
		return nil, "", ErrInvalidServerName
	}
	if len(publicKey) != fndsa512.PublicKeySize {
		return nil, "", fndsa512.ErrInvalidPublicKey
	}

	keyID, err := KeyID(publicKey, serverName, proof)
	if err != nil {
		return nil, "", err
	}
	keyName := FNDSAAlgorithm + ":" + ShortKeyID(keyID)
	keyObject := FNDSAKeyObject(publicKey, FNDSAMetadata{}, proof)

	return map[string]any{
		"server_name":    serverName,
		"verify_keys":    map[string]any{keyName: keyObject},
		"valid_until_ts": validUntilTS,
	}, keyName, nil
}

// FNDSAKeyObject returns the verify_keys entry for an FN-DSA public key.
func FNDSAKeyObject(publicKey []byte, _ FNDSAMetadata, proof FNDSAMintingProof) map[string]any {
	return map[string]any{
		"key":     base64.RawStdEncoding.EncodeToString(publicKey),
		"profile": proof.Algorithm,
		"pow": map[string]any{
			"nonce":    proof.Nonce,
			"solution": uint32sToAny(proof.Solution),
		},
	}
}

func graphObject(publicKey []byte, serverName, profileName string, nonce uint32) map[string]any {
	return map[string]any{
		"action":      graphTag(profileName),
		"nonce":       nonce,
		"profile":     profileName,
		"public_key":  base64.RawStdEncoding.EncodeToString(publicKey),
		"server_name": serverName,
	}
}

func graphTag(profileName string) string {
	if p, ok := profiles[profileName]; ok {
		return p.graphTag
	}
	return profileName + ".graph"
}

func keyIDTag(profileName string) string {
	if p, ok := profiles[profileName]; ok {
		return p.keyIDTag
	}
	return profileName + ".keyid"
}

func mintingObject(publicKey []byte, serverName, profileName string, proof FNDSAMintingProof) map[string]any {
	return map[string]any{
		"action":      keyIDTag(profileName),
		"nonce":       proof.Nonce,
		"profile":     profileName,
		"public_key":  base64.RawStdEncoding.EncodeToString(publicKey),
		"server_name": serverName,
		"solution":    uint32sToAny(proof.Solution),
	}
}

// GraphSeed returns the key-graph seed used to derive the minting proof.
func GraphSeed(publicKey []byte, serverName, profileName string, nonce uint32) ([32]byte, error) {
	var out [32]byte
	canonical, err := matrixjson.Canonical(graphObject(publicKey, serverName, profileName, nonce))
	if err != nil {
		return out, err
	}
	sum := sha3.Sum256(canonical)
	copy(out[:], sum[:])
	return out, nil
}

// KeyID returns the canonical SHA3-256 digest for a minted server key.
func KeyID(publicKey []byte, serverName string, proof FNDSAMintingProof) ([32]byte, error) {
	var out [32]byte
	canonical, err := matrixjson.Canonical(mintingObject(publicKey, serverName, proof.Algorithm, proof))
	if err != nil {
		return out, err
	}

	h := sha3.New256()
	_, _ = h.Write(canonical)
	copy(out[:], h.Sum(nil))
	return out, nil
}

// KeyIDBase64 returns the key ID digest in base64url form.
func KeyIDBase64(publicKey []byte, serverName string, proof FNDSAMintingProof) (string, error) {
	keyID, err := KeyID(publicKey, serverName, proof)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(keyID[:]), nil
}

// ShortKeyID returns the 128-bit lowercase-hex key-name suffix.
func ShortKeyID(keyID [32]byte) string {
	return hex.EncodeToString(keyID[:profiles[ProductionProfile].shortBytes])
}

func validateProof(publicKey []byte, serverName, profileName string, proof FNDSAMintingProof) error {
	p, ok := profiles[profileName]
	if !ok {
		return ErrUnknownProfile
	}
	seed, err := GraphSeed(publicKey, serverName, profileName, proof.Nonce)
	if err != nil {
		return err
	}
	return cuckoo.Verify(p.config, seed[:], proof.Solution)
}

// SignFNDSA signs obj as a Matrix server-key object and stores the signature in
// obj["signatures"][serverName][keyName].
func SignFNDSA(rng io.Reader, obj map[string]any, serverName, keyName string, privateKey []byte) error {
	if serverName == "" {
		return ErrInvalidServerName
	}
	if !strings.HasPrefix(keyName, FNDSAAlgorithm+":") {
		return ErrInvalidKeyName
	}

	signingBytes, err := SigningBytes(obj)
	if err != nil {
		return err
	}
	sig, err := fndsa512.Sign(rng, privateKey, signingBytes)
	if err != nil {
		return err
	}

	serverSigs := map[string]any{}
	signatures, ok := obj["signatures"].(map[string]any)
	if ok {
		if existing, ok := signatures[serverName].(map[string]any); ok {
			serverSigs = existing
		}
	} else {
		if _, exists := obj["signatures"]; exists {
			return ErrInvalidKeyObject
		}
		obj["signatures"] = map[string]any{}
		signatures = obj["signatures"].(map[string]any)
	}

	serverSigs[keyName] = base64.RawStdEncoding.EncodeToString(sig)
	signatures[serverName] = serverSigs
	return nil
}

// SigningBytes returns the Matrix Canonical JSON bytes covered by signatures.
func SigningBytes(obj map[string]any) ([]byte, error) {
	signingObject := make(map[string]any, len(obj))
	for key, value := range obj {
		if key == "signatures" || key == "unsigned" {
			continue
		}
		signingObject[key] = value
	}
	return matrixjson.Canonical(signingObject)
}

// KeyMetadataSHA256 returns the base64url SHA-256 commitment used by the PoW
// resource's key_metadata_sha256 field.
func KeyMetadataSHA256(keyObject map[string]any) (string, error) {
	canonical, err := matrixjson.Canonical(keyObject)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// KeyIDSHA256 returns the archived SHA-256 key fingerprint for publicKey.
func KeyIDSHA256(publicKey []byte) string {
	sum := keyid.SHA256(publicKey)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyFNDSASelfSignature verifies an FN-DSA signature only. Call
// VerifyMintedFNDSAServerKey to accept a key for protocol use.
func VerifyFNDSASelfSignature(obj map[string]any, serverName string) (string, error) {
	return verifyFNDSASignature(obj, serverName, false)
}

// VerifyMintedFNDSAServerKey verifies the closed profile registry, Cuckoo
// proof, content-addressed key name, and FN-DSA self-signature.
func VerifyMintedFNDSAServerKey(obj map[string]any, serverName string) (string, error) {
	return verifyFNDSASignature(obj, serverName, true)
}

func verifyFNDSASignature(obj map[string]any, serverName string, requireProof bool) (string, error) {
	verifyKeys, ok := obj["verify_keys"].(map[string]any)
	if !ok {
		return "", ErrInvalidKeyObject
	}
	signatures, ok := obj["signatures"].(map[string]any)
	if !ok {
		return "", ErrInvalidKeyObject
	}
	serverSigs, ok := signatures[serverName].(map[string]any)
	if !ok {
		return "", ErrInvalidKeyObject
	}

	signingBytes, err := SigningBytes(obj)
	if err != nil {
		return "", err
	}

	for keyName, rawKeyObject := range verifyKeys {
		if !strings.HasPrefix(keyName, FNDSAAlgorithm+":") {
			continue
		}
		keyObject, ok := rawKeyObject.(map[string]any)
		if !ok {
			return "", ErrInvalidKeyObject
		}
		publicKey, err := publicKeyFromObject(keyObject)
		if err != nil {
			return "", err
		}
		if requireProof {
			profileName, proof, err := mintingProofFromObject(keyObject)
			if err != nil {
				return "", err
			}
			if err := validateProof(publicKey, serverName, profileName, proof); err != nil {
				return "", err
			}
			// validateProof has already canonicalized the same validated inputs;
			// mintingObject adds only uint32 solution entries, so KeyID cannot
			// fail here.
			keyID, _ := KeyID(publicKey, serverName, proof)
			if keyName != FNDSAAlgorithm+":"+ShortKeyID(keyID) {
				return "", ErrInvalidKeyName
			}
		}
		rawSig, ok := serverSigs[keyName].(string)
		if !ok {
			return "", ErrInvalidSignature
		}
		sig, err := base64.RawStdEncoding.DecodeString(rawSig)
		if err != nil {
			return "", err
		}
		if !fndsa512.Verify(publicKey, signingBytes, sig) {
			return "", ErrInvalidSignature
		}
		return keyName, nil
	}

	return "", ErrInvalidKeyName
}

func publicKeyFromObject(keyObject map[string]any) ([]byte, error) {
	rawKey, ok := keyObject["key"].(string)
	if !ok {
		return nil, ErrInvalidKeyObject
	}
	publicKey, err := base64.RawStdEncoding.DecodeString(rawKey)
	if err != nil {
		return nil, err
	}
	if len(publicKey) != fndsa512.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d want %d", fndsa512.ErrInvalidPublicKey, len(publicKey), fndsa512.PublicKeySize)
	}
	return publicKey, nil
}

func mintingProofFromObject(keyObject map[string]any) (string, FNDSAMintingProof, error) {
	profileName, ok := keyObject["profile"].(string)
	if !ok || profileName == "" {
		return "", FNDSAMintingProof{}, ErrInvalidKeyObject
	}
	rawPow, ok := keyObject["pow"].(map[string]any)
	if !ok {
		return "", FNDSAMintingProof{}, ErrInvalidKeyObject
	}
	nonce, err := uint32FromAny(rawPow["nonce"])
	if err != nil {
		return "", FNDSAMintingProof{}, err
	}
	solution, err := uint32sFromAny(rawPow["solution"])
	if err != nil {
		return "", FNDSAMintingProof{}, err
	}
	return profileName, FNDSAMintingProof{Algorithm: profileName, Nonce: nonce, Solution: solution}, nil
}

func uint32FromAny(v any) (uint32, error) {
	n, err := uint64FromAny(v)
	if err != nil || n > uint64(^uint32(0)) {
		return 0, ErrInvalidKeyObject
	}
	return uint32(n), nil
}

func uint64FromAny(v any) (uint64, error) {
	switch n := v.(type) {
	case uint8:
		return uint64(n), nil
	case uint16:
		return uint64(n), nil
	case uint32:
		return uint64(n), nil
	case uint64:
		return n, nil
	case uint:
		return uint64(n), nil
	case int:
		if n < 0 {
			return 0, ErrInvalidKeyObject
		}
		return uint64(n), nil
	case int64:
		if n < 0 {
			return 0, ErrInvalidKeyObject
		}
		return uint64(n), nil
	case float64:
		if n < 0 || n != float64(uint64(n)) {
			return 0, ErrInvalidKeyObject
		}
		return uint64(n), nil
	default:
		return 0, ErrInvalidKeyObject
	}
}

func uint32sToAny(values []uint32) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

func uint32sFromAny(v any) ([]uint32, error) {
	if values, ok := v.([]uint32); ok {
		out := make([]uint32, len(values))
		copy(out, values)
		return out, nil
	}
	rawValues, ok := v.([]any)
	if !ok {
		return nil, ErrInvalidKeyObject
	}
	values := make([]uint32, len(rawValues))
	for i, raw := range rawValues {
		n, err := uint64FromAny(raw)
		if err != nil {
			return nil, err
		}
		if n > uint64(^uint32(0)) {
			return nil, ErrInvalidKeyObject
		}
		values[i] = uint32(n)
	}
	return values, nil
}
