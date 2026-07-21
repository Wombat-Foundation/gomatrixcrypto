package fndsa512

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"testing"

	"github.com/pornin/go-fn-dsa/fndsa"
	"golang.org/x/crypto/sha3"
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

func TestSignRejectsInvalidPrivateKey(t *testing.T) {
	if _, err := Sign(nil, []byte("short"), []byte("msg")); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey, got %v", err)
	}
	if _, err := SignPrehashed(nil, []byte("short"), []byte("ctx"), crypto.SHA256, make([]byte, sha256.Size)); !errors.Is(err, ErrInvalidPrivateKey) {
		t.Fatalf("expected ErrInvalidPrivateKey, got %v", err)
	}
}

func TestSignRejectsMalformedSizedPrivateKey(t *testing.T) {
	bad := make([]byte, PrivateKeySize)
	if _, err := Sign(nil, bad, []byte("msg")); err == nil {
		t.Fatalf("expected malformed sized private key to fail")
	}
	if _, err := SignPrehashed(nil, bad, []byte("ctx"), crypto.SHA256, make([]byte, sha256.Size)); err == nil {
		t.Fatalf("expected malformed sized private key to fail")
	}
}

func TestSignRejectsUpstreamInvalidKey(t *testing.T) {
	bad := make([]byte, PrivateKeySize)
	bad[0] = 0x01
	if _, err := Sign(nil, bad, []byte("msg")); err == nil {
		t.Fatalf("expected upstream invalid private key error")
	}
	if _, err := SignPrehashed(nil, bad, []byte("ctx"), crypto.SHA256, make([]byte, sha256.Size)); err == nil {
		t.Fatalf("expected upstream invalid private key error")
	}
}

func TestSignRejectsShortUpstreamSignature(t *testing.T) {
	oldSign := sign
	sign = func(io.Reader, []byte, fndsa.DomainContext, crypto.Hash, []byte) ([]byte, error) {
		return make([]byte, SignatureSize-1), nil
	}
	t.Cleanup(func() { sign = oldSign })

	priv := make([]byte, PrivateKeySize)
	if _, err := Sign(nil, priv, []byte("msg")); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
	if _, err := SignPrehashed(nil, priv, []byte("ctx"), crypto.SHA256, make([]byte, sha256.Size)); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("expected invalid signature error, got %v", err)
	}
}

func TestSignPrehashedRejectsOversizedContext(t *testing.T) {
	priv, _, err := GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := bytes.Repeat([]byte("x"), 256)
	if _, err := SignPrehashed(nil, priv, ctx, crypto.SHA256, make([]byte, sha256.Size)); err == nil {
		t.Fatalf("expected oversized context to fail")
	}
}

func TestDeterministicVector(t *testing.T) {
	rng := func(seed string) io.Reader {
		h := sha3.NewShake256()
		_, _ = h.Write([]byte(seed))
		return h
	}

	priv, pub, err := GenerateKey(rng("msc45xx-fndsa-keygen-seed-v1"))
	if err != nil {
		t.Fatal(err)
	}

	const wantPriv = "Wf+vvfAe//AQfuwggPuw/AQQjQdPwBOwe/QQRuwA/vAQPww+/xBQBPQ+x/wfiQBRQg//uQgw+xPR/hgggfQRPfQve+/Qx/hPPAv+gfhAgffRgvBQufAhSPv/x/ABPPhPPugQgRvhfvvRxP/OffQPvAPevQggwPePAAPgvAQwQAPBQA+/vAgBghA/vBfvgBfu/wBPRf/Qxv/RvgRPxvfOgQfgyffyfARgAuwQxQBw/wRvxQhvxPQQPxQgOwfxPNQQAhdwgf//+/xOSBwAgBQPewuhf/fBBgQQg/AxA/hBNgRQgQP/vgPhPwAAPfeAwwgCPvPxA/hw/Phgu/vwBexQOBfBAdwQfAfggfOfv/QvthA/wfw/whgBPBfAiRg/ufRPhiugvffuvuuwvPevfxSPggQQSBCt/QgARwvxRQ//QPAQg/ifAgRBPfPvuwwfvCARAuvdfAewSNgvxg/QvBQvwuuPegvfgQf++BuxvQuQBQi+vyufQ//vf/QAwegQAQgwxPxOgQNvAAAQgBRuQx+ggf/hPPv///AuvvPuwP/vuvfQP/gQP+wyPfQfPwfPg/vvuQwPxvBfffQOhvgvAgfwAQA+vex+wehfyid+xg+xPBvPQOgQQhvAfROhQvfQBPggARfvBfANgxQQOxAPvwQvihPwwAvwPvQQ/QgePxAPvQAO/SAfR/hO/w/QOwgQPROgQvfehevQ/+xxPgP/hBiOgfPNxvfhgOfdgAQOv/PvvgRwPAQf/RN+/fvAQQvQgAxhw+wPhdQ//www/wcuA+QvPQ//+wPwxxBOQvAggSNvAufvxPffO/gAQ/Peu+v//AQ/Pv/h/QPv+gQP/fPPBgAtwQQCvwvQQeu/exARAAQ/eSPwABBfgwQBQwPPP/ee//wv+whwevvvhffhxBPBwP+whf+/BgQfAfQgBgAgP/QP/wfAPgwuvgQQgufQfQw/vQwOvwB/ANvCBQAA+//9/uAfg/fhhQ+QAxghAiAwPgO/xPRAuAv/vwBBQPfO//xwvgOwhf8QGxClDCsZ8BsF7BH8BtwD9PcBLOQXG/rkHSIF2RP8HuhD+hgFD98bxO/w7/r3AtMOBQMn7db68h0K8/70FCvd8eYH+vT9KwDo+wEhCAT68gfl+98D4eYM9e/9FwetDfT0Bu3px/0l7AsMB/oiJfLnFyQEOlEj+vbtBhQu8QI3FwjzCfLqEgva/tglGxQ9Be3v7eHSO9jRG9oYDg4p8Cza/fDxIxTuHAIWzuf++QMI59DY5vz/Ch/p2Q/Pvurs5SMw994AAA/WDA3V8wcP/QAQ/S0DHdf4/OQSQdAB+9wOD/sa7A4C/PD7+/cG87n6+OMH7C7d+QQKz/MRJ+katRL08/gALQT8DgH8EfsBBucf+RMCJDvXKBQB5PAIEfwvFwkR5AkC+x3ezvDa9xUX+/YB2eHlIyEQIh0jCgkgGhX7PgQY9PQNEvn+Ixgd89f1Frr29+X548UOtiPq8AfcAwLK1/ohHP8GDCH8JC0PCfoPAAM9QP8GByQON/sDFP799ggn/QH/Byz98tsFCBgEJMEV8h/n/gES7ikO+CXlGQgCBfnwGQgcDQsM88z86xr14wss9MjjItki0uXw2NADGwvs3eMEyPf99OIX1Sjn6jv1ABQuOR8DHwcC2yMF5PT7Oe3b+uLu8zj3+fEy/inuIf8kGg3uEAsh+xkw/AMIDi0N"
	const wantPub = "CUMlDwB0VzdvaT1nEeaTr21DtluYBSy6dktakGJh1K6o/yrYfthHeoRcG1gCURulT9CUkULCZYQvt2SM20hlAVUB7ehqZjN5fpAFoCtera1xaV8PdqnkbRJwXdtUQf770KVQWPjL9Z4ZwVVyVRpC1P41SehABNsDII0eBcJK65yGHKvnVL+RGBS15oG2oNjQazrWx1S6PZkAVMtq1RIoYJcsAeq6tMOvAW8ML3DXpw2mkYQZKYyxIHBOeDULD1dyO/FAQIRYpdsQumjBHCqiypHdSDu1GLOajB9hxNmAaepGnzWyK24RYgn4p+vd4WI6uhnHlJRJQqq6iOwoD38mIZtHqUIsbAn1xJrkAlRQEHUObZ4O5RNuhRIvuSBa5290pigmdeXhwY+VBjCrJ/mrBS5SOE+njyKqc7fVAYntsGoCrA2AVsOqMwCQpoi7tbLP3lBOzbhFLsWnWJTUkpT5MOqPAWvaSp5+5YEIJiRHteTjm8iVsIF4UWDJ7pNk5HaTCXaoslCgq0cZS4JLGXWS60I2RPL5nzaY/obiT543b5H+CdXXKjUgn0rrwRd+ndzpDpABfu4QMvda/jTV9/TJDZmy/ojyBdUPX1J9sruaTl2pkTkwL11asfrGoRSZt77Cl8FqcgOoXcJEGAeE8SUSmOkdICTVEWesNm9CVJUTJxVOttDjLM4Mvd6SyA/sO1KufVlLIwlH4Z7gH6KPPtJnwsEbSaB0OuWbTntY6K4xTghWvr62Md2TkqQ0CzsTS5y/LqHDcayOc85dcA6ENKMiLLb25cEXegc3uSSegmgKISdfzjeEt1ffK/JGLO16a1luUth6Al5Kv0pRuHXf7uKMWFF3jQQ+ojVyU0dhnD6kvlE8IL5zuYoIFqBAT8ruIw1scmmo+YjK4dJhtWXjOgd8JoHYiJ9GFYkJu3n266KjzQioHQTAPCZzNEFq62hkVSvDWnYJsD5QWRJIKzjLadUYmF0pOUUoq46rQMJi6EiyI6KoNuHj461IbUp726whYgOlZ61xmsgGsFpWDZby/iHN0CVhTQTQROz7fA415ozfIUEi8EU2GkwJcY40mG7ORfF7ixnUzIeC56RSmKtvAnK1n9fDB6CEAAkP7GDlMlRm7UVUnXpHr5jKqOlxMkbcvLytN8sdE/8+WGKwBYhkq13XdNhayVl9W1Ko3m9BxoF5pQZq"
	const wantSig = "OR1ILU+zEfglTjfS36YPtmYURnEMjBDlviLlO0yq214jygBVxOcAfTuezSWGIw8sjyKw0bij/Wsi86tqFERfCDQErvbK16xY+izE6Y2BI93lmrJ3s84z1adTn5uhN1L91AbGY4R1JN7szM/KV3jYNNua1xLmrrL3TGRAXlcHRPfkYY3Wk1TzS1kL7SLhCbEq01qqbcY/+RkyMbfXNYzAlylx5wp0z0bO9CxQ1cttgwMwa8jgjaNvaya96FTmuKskCuuLtHAqfAXrJIH4GRdNUmUrve3YiinS9ufe4sd6WkVDA6VITfYVONrk88nNWu+QSA/LYRwxCc8hL2aYZTK0fOkx/6rHdylSyiR9LnYZdT6YsMfVI5tommGdhPJcvKgnRwIyrISylC98SmMfq6OyeexBScItzMLt6to+2MO41dUaqOpXBS15NXpB/Fsx8oYzt4NdZ5VGs33PscfUARf9RDoKBWmIfnN47yX/HcbEcbrpCszaFagOc1PBRxujMxUWrlGW+EkQHc0yetPJqDsUR5lGWaXqRZPUjTCvCgk403LgjURzR0rFm8cRy5XbtyRSLnFTjGkQ2FTq5AR+ulI3pZvT74YNYqxREbNWWKTi4zr2U5BnlwUveCKK41fmiBPOT8WPQOmYs11IpKxHiaQ8D4N9Esmz+/6b1VJgXU0E/UxvY7HNZgrR1qjBr3VfXsnLN5mFotf5Rwp1thUGjT3e1jMnJUKuKzednTIxgpTjLOO6im3XnMRnErNjWXSiEGFYolDcylQmXfLVeBvB+DWjY5UwnIWeF2euSXMxy04rGVyH6+Rn443VwrEQRTWavqHdSdprJpRJEz2DNJOu1whd35Zz3JgyeeOaywnaXYMqpDsegAAAAAAAAAAA"

	if got := base64.RawStdEncoding.EncodeToString(priv); got != wantPriv {
		t.Fatalf("private key mismatch")
	}
	if got := base64.RawStdEncoding.EncodeToString(pub); got != wantPub {
		t.Fatalf("public key mismatch")
	}

	sig, err := Sign(rng("msc45xx-fndsa-sign-seed-v1"), priv, []byte("matrix federation post-quantum test vector"))
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawStdEncoding.EncodeToString(sig); got != wantSig {
		t.Fatalf("signature mismatch")
	}
	if !Verify(pub, []byte("matrix federation post-quantum test vector"), sig) {
		t.Fatalf("vector signature did not verify")
	}
}

func TestVerifyRejectsInvalidInputs(t *testing.T) {
	if Verify([]byte("short"), []byte("msg"), make([]byte, SignatureSize)) {
		t.Fatalf("expected invalid public key to fail")
	}
	if Verify(make([]byte, PublicKeySize), []byte("msg"), []byte("short")) {
		t.Fatalf("expected invalid signature to fail")
	}
	if VerifyPrehashed([]byte("short"), []byte("ctx"), crypto.SHA256, make([]byte, sha256.Size), make([]byte, SignatureSize)) {
		t.Fatalf("expected invalid public key to fail")
	}
}
