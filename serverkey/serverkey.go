package serverkey

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"gomatrixlib/fndsa512"
	"gomatrixlib/keyid"
	"gomatrixlib/matrixjson"
)

const (
	FNDSAAlgorithm      = "fn-dsa-512"
	DefaultFIPSRevision = "ipd-2025-08"
)

var (
	ErrInvalidServerName = errors.New("invalid server name")
	ErrInvalidKeyName    = errors.New("invalid key name")
	ErrInvalidKeyObject  = errors.New("invalid server key object")
	ErrInvalidSignature  = errors.New("invalid server key signature")
)

type FNDSAMetadata struct {
	FIPS206Revision string
	Claims          []string
}

// NewSignedFNDSA builds a Matrix server-key object with one FN-DSA verify key
// and adds the matching self-signature.
func NewSignedFNDSA(rng io.Reader, serverName string, privateKey, publicKey []byte, validUntilTS int64, metadata FNDSAMetadata) (map[string]any, string, error) {
	obj, keyName, err := NewUnsignedFNDSA(serverName, publicKey, validUntilTS, metadata)
	if err != nil {
		return nil, "", err
	}
	if err := SignFNDSA(rng, obj, serverName, keyName, privateKey); err != nil {
		return nil, "", err
	}
	return obj, keyName, nil
}

// NewUnsignedFNDSA builds the key object before signatures are attached.
func NewUnsignedFNDSA(serverName string, publicKey []byte, validUntilTS int64, metadata FNDSAMetadata) (map[string]any, string, error) {
	if serverName == "" {
		return nil, "", ErrInvalidServerName
	}
	if len(publicKey) != fndsa512.PublicKeySize {
		return nil, "", fndsa512.ErrInvalidPublicKey
	}

	shortID := keyid.ShortID(publicKey)
	keyName := FNDSAAlgorithm + ":" + shortID
	keyObject := FNDSAKeyObject(publicKey, metadata)

	return map[string]any{
		"server_name":     serverName,
		"verify_keys":     map[string]any{keyName: keyObject},
		"old_verify_keys": map[string]any{},
		"valid_until_ts":  validUntilTS,
	}, keyName, nil
}

// FNDSAKeyObject returns the verify_keys entry for an FN-DSA public key.
func FNDSAKeyObject(publicKey []byte, metadata FNDSAMetadata) map[string]any {
	keyObject := map[string]any{
		"key": base64.RawStdEncoding.EncodeToString(publicKey),
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

// KeyIDSHA256 returns the base64url canonical full key ID digest for publicKey.
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
		if keyName != FNDSAAlgorithm+":"+keyid.ShortID(publicKey) {
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
