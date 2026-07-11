package cuckoo

import "testing"

func TestEdgeForNonceDeterministic(t *testing.T) {
	cfg := Config{EdgeBits: 10}
	seed := []byte("matrix-cuckoo-seed")

	e1, err := EdgeForNonce(cfg, seed, 7)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := EdgeForNonce(cfg, seed, 7)
	if err != nil {
		t.Fatal(err)
	}
	if e1 != e2 {
		t.Fatalf("edge derivation not deterministic")
	}
}

func TestFindProofAndVerify(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := []byte("tiny-cuckoo-test")

	proof, err := FindProof(cfg, seed, 1<<12)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != cfg.ProofSize {
		t.Fatalf("unexpected proof size: got %d want %d", len(proof), cfg.ProofSize)
	}
	if err := Verify(cfg, seed, proof); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := []byte("tiny-cuckoo-test")

	proof, err := FindProof(cfg, seed, 1<<12)
	if err != nil {
		t.Fatal(err)
	}
	proof[0]++
	if err := Verify(cfg, seed, proof); err == nil {
		t.Fatalf("expected tampered proof to fail")
	}
}
