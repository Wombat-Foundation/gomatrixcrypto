package fndsa512

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

func TestSignVerify(t *testing.T) {
	priv, pub, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(priv) != PrivateKeySize || len(pub) != PublicKeySize {
		t.Fatalf("unexpected key sizes: priv=%d pub=%d", len(priv), len(pub))
	}

	msg := []byte("matrix federation post-quantum test vector")
	sig, err := Sign(nil, priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != SignatureSize {
		t.Fatalf("unexpected signature size: got %d want %d", len(sig), SignatureSize)
	}
	if !Verify(pub, msg, sig) {
		t.Fatalf("signature did not verify")
	}
	if Verify(pub, []byte("tampered"), sig) {
		t.Fatalf("tampered message verified")
	}
}

func TestSignVerifyPrehashed(t *testing.T) {
	priv, pub, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	sum := sha256.Sum256([]byte("canonical-json"))
	ctx := []byte("matrix")
	sig, err := SignPrehashed(nil, priv, ctx, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPrehashed(pub, ctx, crypto.SHA256, sum[:], sig) {
		t.Fatalf("prehashed signature did not verify")
	}

	badDigest := bytes.Repeat([]byte{0x42}, len(sum))
	if VerifyPrehashed(pub, ctx, crypto.SHA256, badDigest, sig) {
		t.Fatalf("tampered digest verified")
	}
}
