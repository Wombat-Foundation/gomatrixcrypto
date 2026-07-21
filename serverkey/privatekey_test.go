package serverkey

import (
	"encoding/base64"
	"errors"
	"testing"

	"gomatrixlib/fndsa512"

	"golang.org/x/crypto/chacha20poly1305"
)

// failingReader errors on every read.
type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

// shortReader succeeds for the first n bytes read (across calls), then fails.
type shortReader struct {
	remaining int
	err       error
}

func (r *shortReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, r.err
	}
	n := min(len(p), r.remaining)
	for i := range n {
		p[i] = 0x42
	}
	r.remaining -= n
	return n, nil
}

func validPrivateKeyParams() PrivateKeyEncryptionParams {
	return PrivateKeyEncryptionParams{Time: 1, MemoryKiB: 8 * 1024, Threads: 1}
}

func TestEncryptPrivateKeyPropagatesSaltRandomnessError(t *testing.T) {
	wantErr := errors.New("boom")
	_, err := EncryptPrivateKey(failingReader{wantErr}, make([]byte, fndsa512.PrivateKeySize), []byte("passphrase"), validPrivateKeyParams())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected salt randomness error, got %v", err)
	}
}

func TestEncryptPrivateKeyPropagatesNonceRandomnessError(t *testing.T) {
	wantErr := errors.New("boom")
	// Succeeds for exactly the salt read, then fails on the nonce read.
	rng := &shortReader{remaining: 16, err: wantErr}
	_, err := EncryptPrivateKey(rng, make([]byte, fndsa512.PrivateKeySize), []byte("passphrase"), validPrivateKeyParams())
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected nonce randomness error, got %v", err)
	}
}

func TestEncryptPrivateKeyRejectsWrongSizeSaltOrNonce(t *testing.T) {
	params := validPrivateKeyParams()
	params.Salt = []byte{0x01, 0x02, 0x03}
	if _, err := EncryptPrivateKey(nil, make([]byte, fndsa512.PrivateKeySize), []byte("passphrase"), params); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for wrong-size salt, got %v", err)
	}

	params = validPrivateKeyParams()
	params.Nonce = []byte{0x01, 0x02, 0x03}
	if _, err := EncryptPrivateKey(nil, make([]byte, fndsa512.PrivateKeySize), []byte("passphrase"), params); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for wrong-size nonce, got %v", err)
	}
}

// privateKeyKeySize must match chacha20poly1305.KeySize: argon2.IDKey always
// derives a key of this length, so chacha20poly1305.NewX in privateKeyAEAD
// can never fail in practice. This test documents that invariant; the error
// branches in EncryptPrivateKey/DecryptPrivateKey that check its return are
// defensive and otherwise unreachable.
func TestPrivateKeyKeySizeMatchesAEADKeySize(t *testing.T) {
	if privateKeyKeySize != chacha20poly1305.KeySize {
		t.Fatalf("privateKeyKeySize %d != chacha20poly1305.KeySize %d", privateKeyKeySize, chacha20poly1305.KeySize)
	}
}

func TestDecryptPrivateKeyRejectsEmptyPassphrase(t *testing.T) {
	if _, err := DecryptPrivateKey(map[string]any{}, nil); !errors.Is(err, ErrInvalidPassphrase) {
		t.Fatalf("expected invalid passphrase error, got %v", err)
	}
}

func TestDecryptPrivateKeyRejectsWrongSizeDecryptedKey(t *testing.T) {
	params := validPrivateKeyParams()
	params.Salt = make([]byte, privateKeySaltSize)
	params.Nonce = make([]byte, chacha20poly1305.NonceSizeX)
	aead, err := privateKeyAEAD([]byte("passphrase"), params)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := aead.Seal(nil, params.Nonce, []byte("too short"), []byte(EncryptedPrivateKeyAlgorithm))

	encrypted := map[string]any{
		"algorithm": EncryptedPrivateKeyAlgorithm,
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(params.Time),
			"memory_kib": uint64(params.MemoryKiB),
			"threads":    uint64(params.Threads),
			"salt":       base64.RawStdEncoding.EncodeToString(params.Salt),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(params.Nonce),
		},
		"ciphertext": base64.RawStdEncoding.EncodeToString(ciphertext),
	}

	if _, err := DecryptPrivateKey(encrypted, []byte("passphrase")); !errors.Is(err, fndsa512.ErrInvalidPrivateKey) {
		t.Fatalf("expected invalid private key size error, got %v", err)
	}
}

func TestReencryptPrivateKeyPropagatesDecryptError(t *testing.T) {
	priv := make([]byte, fndsa512.PrivateKeySize)
	encrypted, err := EncryptPrivateKey(nil, priv, []byte("old passphrase"), validPrivateKeyParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReencryptPrivateKey(nil, encrypted, []byte("wrong passphrase"), []byte("new passphrase"), validPrivateKeyParams()); err == nil {
		t.Fatalf("expected reencrypt to propagate decrypt error")
	}
}

func TestPrivateKeyEncryptionParamsFromObjectRejectsInvalidNumericFields(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(1),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, privateKeySaltSize)),
		}
	}
	fields := []string{"time", "memory_kib", "threads"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			kdf := base()
			kdf[field] = "not a number"
			encrypted := map[string]any{
				"kdf": kdf,
				"aead": map[string]any{
					"algorithm": privateKeyAEADAlgorithm,
					"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)),
				},
			}
			if _, err := privateKeyEncryptionParamsFromObject(encrypted); !errors.Is(err, ErrInvalidKeyObject) {
				t.Fatalf("expected invalid key object for bad %s, got %v", field, err)
			}
		})
	}
}

func TestPrivateKeyEncryptionParamsFromObjectRejectsMissingSaltOrNonce(t *testing.T) {
	validKDF := map[string]any{
		"algorithm":  privateKeyKDFAlgorithm,
		"time":       uint64(1),
		"memory_kib": uint64(8 * 1024),
		"threads":    uint64(1),
		"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, privateKeySaltSize)),
	}
	validAEAD := map[string]any{
		"algorithm": privateKeyAEADAlgorithm,
		"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)),
	}

	kdfMissingSalt := cloneMap(validKDF)
	delete(kdfMissingSalt, "salt")
	if _, err := privateKeyEncryptionParamsFromObject(map[string]any{
		"kdf":  kdfMissingSalt,
		"aead": cloneMap(validAEAD),
	}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for missing salt, got %v", err)
	}

	aeadMissingNonce := cloneMap(validAEAD)
	delete(aeadMissingNonce, "nonce")
	if _, err := privateKeyEncryptionParamsFromObject(map[string]any{
		"kdf":  cloneMap(validKDF),
		"aead": aeadMissingNonce,
	}); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for missing nonce, got %v", err)
	}
}

func TestPrivateKeyEncryptionParamsFromObjectRejectsOutOfRangeNumbers(t *testing.T) {
	tooLarge := uint64(1) << 40
	base := func() map[string]any {
		return map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(1),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, privateKeySaltSize)),
		}
	}
	validAEAD := map[string]any{
		"algorithm": privateKeyAEADAlgorithm,
		"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)),
	}
	fields := []string{"time", "memory_kib", "threads"}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			kdf := base()
			kdf[field] = tooLarge
			encrypted := map[string]any{
				"kdf":  kdf,
				"aead": cloneMap(validAEAD),
			}
			if _, err := privateKeyEncryptionParamsFromObject(encrypted); !errors.Is(err, ErrInvalidKeyObject) {
				t.Fatalf("expected invalid key object for out-of-range %s, got %v", field, err)
			}
		})
	}
}

func TestPrivateKeyEncryptionParamsFromObjectRejectsZeroTime(t *testing.T) {
	encrypted := map[string]any{
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(0),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, privateKeySaltSize)),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)),
		},
	}
	if _, err := privateKeyEncryptionParamsFromObject(encrypted); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for zero time cost, got %v", err)
	}
}

func TestPrivateKeyEncryptionParamsFromObjectRejectsWrongSizeSaltOrNonce(t *testing.T) {
	shortSalt := map[string]any{
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(1),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, 4)),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, chacha20poly1305.NonceSizeX)),
		},
	}
	if _, err := privateKeyEncryptionParamsFromObject(shortSalt); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for wrong-size salt, got %v", err)
	}

	shortNonce := map[string]any{
		"kdf": map[string]any{
			"algorithm":  privateKeyKDFAlgorithm,
			"time":       uint64(1),
			"memory_kib": uint64(8 * 1024),
			"threads":    uint64(1),
			"salt":       base64.RawStdEncoding.EncodeToString(make([]byte, privateKeySaltSize)),
		},
		"aead": map[string]any{
			"algorithm": privateKeyAEADAlgorithm,
			"nonce":     base64.RawStdEncoding.EncodeToString(make([]byte, 4)),
		},
	}
	if _, err := privateKeyEncryptionParamsFromObject(shortNonce); !errors.Is(err, ErrInvalidKeyObject) {
		t.Fatalf("expected invalid key object for wrong-size nonce, got %v", err)
	}
}
