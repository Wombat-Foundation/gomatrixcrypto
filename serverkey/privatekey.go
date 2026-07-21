package serverkey

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"gomatrixlib/fndsa512"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	EncryptedPrivateKeyAlgorithm = "tk.nutra.msc45xx.private-key.xchacha20poly1305-argon2id.v1"
	privateKeyKDFAlgorithm       = "argon2id"
	privateKeyAEADAlgorithm      = "xchacha20poly1305"
	privateKeySaltSize           = 16
	privateKeyKeySize            = 32
)

var ErrInvalidPassphrase = errors.New("invalid private key passphrase")

type PrivateKeyEncryptionParams struct {
	Time      uint32
	MemoryKiB uint32
	Threads   uint8
	Salt      []byte
	Nonce     []byte
}

func DefaultPrivateKeyEncryptionParams() PrivateKeyEncryptionParams {
	return PrivateKeyEncryptionParams{
		Time:      3,
		MemoryKiB: 64 * 1024,
		Threads:   4,
	}
}

func EncryptPrivateKey(rng io.Reader, privateKey, passphrase []byte, params PrivateKeyEncryptionParams) (map[string]any, error) {
	if err := validatePrivateKeyEncryptionInputs(privateKey, passphrase, params); err != nil {
		return nil, err
	}
	if rng == nil {
		rng = rand.Reader
	}
	if len(params.Salt) == 0 {
		params.Salt = make([]byte, privateKeySaltSize)
		if _, err := io.ReadFull(rng, params.Salt); err != nil {
			return nil, err
		}
	}
	if len(params.Nonce) == 0 {
		params.Nonce = make([]byte, chacha20poly1305.NonceSizeX)
		if _, err := io.ReadFull(rng, params.Nonce); err != nil {
			return nil, err
		}
	}
	if len(params.Salt) != privateKeySaltSize || len(params.Nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalidKeyObject
	}

	aead, err := privateKeyAEADFn(passphrase, params)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, params.Nonce, privateKey, []byte(EncryptedPrivateKeyAlgorithm))

	return map[string]any{
		"algorithm": EncryptedPrivateKeyAlgorithm,
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       params.Time,
			"memory_kib": params.MemoryKiB,
			"threads":    params.Threads,
			"salt":       base64.RawStdEncoding.EncodeToString(params.Salt),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(params.Nonce),
		},
		"ciphertext": base64.RawStdEncoding.EncodeToString(ciphertext),
	}, nil
}

func DecryptPrivateKey(encrypted map[string]any, passphrase []byte) ([]byte, error) {
	if len(passphrase) == 0 {
		return nil, ErrInvalidPassphrase
	}
	if algorithm, ok := encrypted["algorithm"].(string); !ok || algorithm != EncryptedPrivateKeyAlgorithm {
		return nil, ErrInvalidKeyObject
	}
	params, err := privateKeyEncryptionParamsFromObject(encrypted)
	if err != nil {
		return nil, err
	}
	rawCiphertext, ok := encrypted["ciphertext"].(string)
	if !ok {
		return nil, ErrInvalidKeyObject
	}
	ciphertext, err := base64.RawStdEncoding.DecodeString(rawCiphertext)
	if err != nil {
		return nil, err
	}

	aead, err := privateKeyAEADFn(passphrase, params)
	if err != nil {
		return nil, err
	}
	privateKey, err := aead.Open(nil, params.Nonce, ciphertext, []byte(EncryptedPrivateKeyAlgorithm))
	if err != nil {
		return nil, err
	}
	if len(privateKey) != fndsa512.PrivateKeySize {
		return nil, fndsa512.ErrInvalidPrivateKey
	}
	return privateKey, nil
}

func ReencryptPrivateKey(rng io.Reader, encrypted map[string]any, oldPassphrase, newPassphrase []byte, params PrivateKeyEncryptionParams) (map[string]any, error) {
	privateKey, err := DecryptPrivateKey(encrypted, oldPassphrase)
	if err != nil {
		return nil, err
	}
	return EncryptPrivateKey(rng, privateKey, newPassphrase, params)
}

func validatePrivateKeyEncryptionInputs(privateKey, passphrase []byte, params PrivateKeyEncryptionParams) error {
	if len(privateKey) != fndsa512.PrivateKeySize {
		return fndsa512.ErrInvalidPrivateKey
	}
	if len(passphrase) == 0 {
		return ErrInvalidPassphrase
	}
	if params.Time == 0 || params.MemoryKiB == 0 || params.Threads == 0 {
		return ErrInvalidKeyObject
	}
	return nil
}

func privateKeyAEAD(passphrase []byte, params PrivateKeyEncryptionParams) (cipher.AEAD, error) {
	key := argon2.IDKey(passphrase, params.Salt, params.Time, params.MemoryKiB, params.Threads, privateKeyKeySize)
	return chacha20poly1305.NewX(key)
}

var privateKeyAEADFn = privateKeyAEAD

func privateKeyEncryptionParamsFromObject(encrypted map[string]any) (PrivateKeyEncryptionParams, error) {
	rawKDF, ok := encrypted["kdf"].(map[string]any)
	if !ok {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	if algorithm, ok := rawKDF["algorithm"].(string); !ok || algorithm != privateKeyKDFAlgorithm {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	timeCost, err := uint64FromAny(rawKDF["time"])
	if err != nil {
		return PrivateKeyEncryptionParams{}, err
	}
	memoryKiB, err := uint64FromAny(rawKDF["memory_kib"])
	if err != nil {
		return PrivateKeyEncryptionParams{}, err
	}
	threads, err := uint64FromAny(rawKDF["threads"])
	if err != nil {
		return PrivateKeyEncryptionParams{}, err
	}
	rawSalt, ok := rawKDF["salt"].(string)
	if !ok {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	salt, err := base64.RawStdEncoding.DecodeString(rawSalt)
	if err != nil {
		return PrivateKeyEncryptionParams{}, err
	}

	rawAEAD, ok := encrypted["aead"].(map[string]any)
	if !ok {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	if algorithm, ok := rawAEAD["algorithm"].(string); !ok || algorithm != privateKeyAEADAlgorithm {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	rawNonce, ok := rawAEAD["nonce"].(string)
	if !ok {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	nonce, err := base64.RawStdEncoding.DecodeString(rawNonce)
	if err != nil {
		return PrivateKeyEncryptionParams{}, err
	}
	if timeCost > uint64(^uint32(0)) || memoryKiB > uint64(^uint32(0)) || threads > uint64(^uint8(0)) {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	params := PrivateKeyEncryptionParams{
		Time:      uint32(timeCost),
		MemoryKiB: uint32(memoryKiB),
		Threads:   uint8(threads),
		Salt:      salt,
		Nonce:     nonce,
	}
	if err := validatePrivateKeyEncryptionInputs(make([]byte, fndsa512.PrivateKeySize), passphraseSentinel, params); err != nil {
		return PrivateKeyEncryptionParams{}, err
	}
	if len(params.Salt) != privateKeySaltSize || len(params.Nonce) != chacha20poly1305.NonceSizeX {
		return PrivateKeyEncryptionParams{}, ErrInvalidKeyObject
	}
	return params, nil
}

var passphraseSentinel = []byte{1}
