// Package fndsa512 wraps FN-DSA-512 signing and verification primitives.
package fndsa512

import (
	"crypto"
	"errors"
	"io"

	"github.com/pornin/go-fn-dsa/fndsa"
)

const (
	LogN           = 9
	PublicKeySize  = 897
	PrivateKeySize = 1281
	SignatureSize  = 666
)

var (
	ErrInvalidPrivateKey = errors.New("invalid fn-dsa-512 private key")
	ErrInvalidPublicKey  = errors.New("invalid fn-dsa-512 public key")
	ErrInvalidSignature  = errors.New("invalid fn-dsa-512 signature")
)

var sign = fndsa.Sign

func checkPrivateKey(key []byte) error {
	if len(key) != PrivateKeySize {
		return ErrInvalidPrivateKey
	}
	return nil
}

func checkPublicKey(key []byte) error {
	if len(key) != PublicKeySize {
		return ErrInvalidPublicKey
	}
	return nil
}

func checkSignature(sig []byte) error {
	if len(sig) != SignatureSize {
		return ErrInvalidSignature
	}
	return nil
}

func GenerateKey(rng io.Reader) (privateKey, publicKey []byte, err error) {
	privateKey, publicKey, err = fndsa.KeyGen(LogN, rng)
	return privateKey, publicKey, err
}

// Sign signs the raw message in pure mode with an empty domain context.
func Sign(rng io.Reader, privateKey, message []byte) ([]byte, error) {
	if err := checkPrivateKey(privateKey); err != nil {
		return nil, err
	}
	sig, err := sign(rng, privateKey, fndsa.DOMAIN_NONE, 0, message)
	if err != nil {
		return nil, err
	}
	// TODO: upstream FN-DSA signing always returns the expected fixed-length
	// signature for this profile, so this branch is effectively unreachable in
	// normal use. Keep it as a defensive check for dependency regressions.
	if err := checkSignature(sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// SignPrehashed signs pre-hashed input with the supplied context and hash ID.
func SignPrehashed(rng io.Reader, privateKey []byte, context []byte, hash crypto.Hash, digest []byte) ([]byte, error) {
	if err := checkPrivateKey(privateKey); err != nil {
		return nil, err
	}
	sig, err := sign(rng, privateKey, fndsa.DomainContext(context), hash, digest)
	if err != nil {
		return nil, err
	}
	// TODO: upstream FN-DSA signing always returns the expected fixed-length
	// signature for this profile, so this branch is effectively unreachable in
	// normal use. Keep it as a defensive check for dependency regressions.
	if err := checkSignature(sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify verifies a raw-message signature in pure mode with an empty domain context.
func Verify(publicKey, message, signature []byte) bool {
	return checkPublicKey(publicKey) == nil &&
		checkSignature(signature) == nil &&
		fndsa.Verify(publicKey, fndsa.DOMAIN_NONE, 0, message, signature)
}

func VerifyPrehashed(publicKey []byte, context []byte, hash crypto.Hash, digest, signature []byte) bool {
	return checkPublicKey(publicKey) == nil &&
		checkSignature(signature) == nil &&
		fndsa.Verify(publicKey, fndsa.DomainContext(context), hash, digest, signature)
}
