// Package serverkey builds and verifies Matrix server-key objects.
package serverkey

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Wombat-Foundation/gomatrixcrypto/fndsa512"
	"github.com/Wombat-Foundation/gomatrixcrypto/keyid"
	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"

	"golang.org/x/crypto/sha3"
)

const (
	FNDSAAlgorithm      = "fn-dsa-512"
	DefaultFIPSRevision = "ipd-2025-08"
	ProductionPoW       = "tk.nutra.msc45xx.pow.cuckoo-cycle-42-29-sha3-256-cogen"
)

var (
	ErrInvalidServerName = errors.New("invalid server name")
	ErrInvalidKeyName    = errors.New("invalid key name")
	ErrInvalidKeyObject  = errors.New("invalid server key object")
	ErrInvalidSignature  = errors.New("invalid server key signature")
)

// FNDSAMetadata carries optional metadata fields for the published key object.
type FNDSAMetadata struct {
	FIPS206Revision string
	Claims          []string
}

// FNDSAMintingProof records the proof data that binds a key to its graph seed.
type FNDSAMintingProof struct {
	Algorithm string
	Nonce     uint64
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
func NewUnsignedFNDSA(serverName string, publicKey []byte, validUntilTS int64, metadata FNDSAMetadata, proof FNDSAMintingProof) (map[string]any, string, error) {
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
	keyObject := FNDSAKeyObject(publicKey, metadata, proof)

	return map[string]any{
		"server_name":         serverName,
		"verify_keys":         map[string]any{keyName: keyObject},
		"old_verify_keys":     map[string]any{},
		"trusted_notary_keys": []any{},
		"valid_until_ts":      validUntilTS,
	}, keyName, nil
}

// FNDSAKeyObject returns the verify_keys entry for an FN-DSA public key.
func FNDSAKeyObject(publicKey []byte, metadata FNDSAMetadata, proof FNDSAMintingProof) map[string]any {
	keyObject := map[string]any{
		"key": base64.RawStdEncoding.EncodeToString(publicKey),
		"pow": map[string]any{
			"algorithm": proof.Algorithm,
			"nonce":     proof.Nonce,
			"solution":  uint32sToAny(proof.Solution),
		},
	}
	if metadata.FIPS206Revision != "" {
		keyObject["fips_206_revision"] = metadata.FIPS206Revision
	}
	if len(metadata.Claims) > 0 {
		claims := make([]string, len(metadata.Claims))
		copy(claims, metadata.Claims)
		keyObject["claims"] = claims
	}
	return keyObject
}

func graphObject(publicKey []byte, serverName string) map[string]any {
	return map[string]any{
		"action":      "fn-dsa-key-graph",
		"public_key":  base64.RawStdEncoding.EncodeToString(publicKey),
		"server_name": serverName,
	}
}

func mintingObject(publicKey []byte, serverName string, proof FNDSAMintingProof) map[string]any {
	return map[string]any{
		"action":      "fn-dsa-minting-object",
		"algorithm":   proof.Algorithm,
		"nonce":       proof.Nonce,
		"public_key":  base64.RawStdEncoding.EncodeToString(publicKey),
		"server_name": serverName,
		"solution":    uint32sToAny(proof.Solution),
	}
}

// GraphSeed returns the key-graph seed used to derive the minting proof.
func GraphSeed(publicKey []byte, serverName string, nonce uint64) ([32]byte, error) {
	var out [32]byte
	canonical, err := matrixjson.Canonical(graphObject(publicKey, serverName))
	if err != nil {
		return out, err
	}
	var nonceBytes [8]byte
	binary.LittleEndian.PutUint64(nonceBytes[:], nonce)

	h := sha3.New256()
	_, _ = h.Write(canonical)
	_, _ = h.Write(nonceBytes[:])
	copy(out[:], h.Sum(nil))
	return out, nil
}

// KeyID returns the canonical SHA3-256 digest for a minted server key.
func KeyID(publicKey []byte, serverName string, proof FNDSAMintingProof) ([32]byte, error) {
	var out [32]byte
	canonical, err := matrixjson.Canonical(mintingObject(publicKey, serverName, proof))
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

// ShortKeyID returns the truncated base64url fingerprint used in key names.
func ShortKeyID(keyID [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(keyID[:])[:20]
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

// VerifyFNDSASelfSignature verifies the self-signature for serverName and
// returns the verified key name.
func VerifyFNDSASelfSignature(obj map[string]any, serverName string) (string, error) {
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
		proof, err := mintingProofFromObject(keyObject)
		if err != nil {
			return "", err
		}
		keyID, err := KeyID(publicKey, serverName, proof)
		if err != nil {
			return "", err
		}
		if keyName != FNDSAAlgorithm+":"+ShortKeyID(keyID) {
			return "", ErrInvalidKeyName
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

func mintingProofFromObject(keyObject map[string]any) (FNDSAMintingProof, error) {
	rawPow, ok := keyObject["pow"].(map[string]any)
	if !ok {
		return FNDSAMintingProof{}, ErrInvalidKeyObject
	}
	algorithm, ok := rawPow["algorithm"].(string)
	if !ok || algorithm == "" {
		return FNDSAMintingProof{}, ErrInvalidKeyObject
	}
	nonce, err := uint64FromAny(rawPow["nonce"])
	if err != nil {
		return FNDSAMintingProof{}, err
	}
	solution, err := uint32sFromAny(rawPow["solution"])
	if err != nil {
		return FNDSAMintingProof{}, err
	}
	return FNDSAMintingProof{Algorithm: algorithm, Nonce: nonce, Solution: solution}, nil
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
