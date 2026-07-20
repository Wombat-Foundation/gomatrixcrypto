package cuckoo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func testSeed() []byte {
	seed := GraphSeed([]byte("tiny-cuckoo-test"), 0)
	return seed[:]
}

func TestEdgeForNonceDeterministic(t *testing.T) {
	cfg := Config{EdgeBits: 10}
	seed := GraphSeed([]byte("matrix-cuckoo-seed"), 7)

	e1, err := EdgeForNonce(cfg, seed[:], 7)
	if err != nil {
		t.Fatal(err)
	}
	e2, err := EdgeForNonce(cfg, seed[:], 7)
	if err != nil {
		t.Fatal(err)
	}
	if e1 != e2 {
		t.Fatalf("edge derivation not deterministic")
	}
}

func TestFindProofAndVerify(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := testSeed()

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
	seed := testSeed()

	proof, err := FindProof(cfg, seed, 1<<12)
	if err != nil {
		t.Fatal(err)
	}
	proof[0]++
	if err := Verify(cfg, seed, proof); err == nil {
		t.Fatalf("expected tampered proof to fail")
	}
}

func TestGraphSeedStable(t *testing.T) {
	got := GraphSeed([]byte("challenge"), 3)
	want := sha256.Sum256([]byte{
		'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e',
		0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	})
	if got != want {
		t.Fatalf("graph seed mismatch")
	}
}

func TestGraphSeedVector(t *testing.T) {
	got := GraphSeed([]byte("tiny-cuckoo-test"), 0)
	const wantHex = "cc53bbfaea7f82519d68c626b808a991decdad0af34fff068d5b506fa45b6bc9"
	if gotHex := hex.EncodeToString(got[:]); gotHex != wantHex {
		t.Fatalf("graph seed mismatch: got %s want %s", gotHex, wantHex)
	}
}

func TestReducedWorkVector(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := GraphSeed([]byte("tiny-cuckoo-test"), 0)

	edges := map[uint32]Edge{
		0:    {U: 177, V: 244},
		48:   {U: 136, V: 244},
		2951: {U: 136, V: 75},
		3093: {U: 177, V: 75},
	}
	for nonce, want := range edges {
		got, err := EdgeForNonce(cfg, seed[:], nonce)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("edge(%d) mismatch: got %#v want %#v", nonce, got, want)
		}
	}

	proof := []uint32{0, 48, 2951, 3093}
	if err := Verify(cfg, seed[:], proof); err != nil {
		t.Fatalf("vector proof failed: %v", err)
	}
}

func TestEdgeForNonceRejectsInvalidInput(t *testing.T) {
	if _, err := EdgeForNonce(Config{EdgeBits: 1}, make([]byte, sha256.Size), 0); !errors.Is(err, ErrInvalidEdgeBits) {
		t.Fatalf("expected ErrInvalidEdgeBits, got %v", err)
	}
	if _, err := EdgeForNonce(Config{EdgeBits: 8}, []byte("short"), 0); !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("expected ErrInvalidSeed, got %v", err)
	}
}

func TestVerifyRejectsUnsortedProof(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := testSeed()
	proof, err := FindProof(cfg, seed, 1<<12)
	if err != nil {
		t.Fatal(err)
	}
	proof[0], proof[1] = proof[1], proof[0]
	if err := Verify(cfg, seed, proof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof, got %v", err)
	}
}

func TestVerifyRejectsWrongProofSizeAndDuplicates(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := testSeed()

	if err := Verify(cfg, seed, []uint32{1, 2, 3}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof size, got %v", err)
	}

	proof, err := FindProof(cfg, seed, 1<<12)
	if err != nil {
		t.Fatal(err)
	}
	proof[1] = proof[0]
	if err := Verify(cfg, seed, proof); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected duplicate proof entries to fail, got %v", err)
	}
}

func TestVerifyRejectsInvalidConfigAndSeed(t *testing.T) {
	if err := Verify(Config{EdgeBits: 1}, testSeed(), []uint32{0}); !errors.Is(err, ErrInvalidEdgeBits) {
		t.Fatalf("expected invalid edge bits, got %v", err)
	}
	if err := Verify(Config{EdgeBits: 8, ProofSize: 4}, []byte("short"), []uint32{0, 1, 2, 3}); !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("expected invalid seed, got %v", err)
	}
}

func TestFindProofRejectsInvalidConfigAndSeed(t *testing.T) {
	if _, err := FindProof(Config{EdgeBits: 1}, testSeed(), 1); !errors.Is(err, ErrInvalidEdgeBits) {
		t.Fatalf("expected invalid edge bits, got %v", err)
	}
	if _, err := FindProof(Config{EdgeBits: 8, ProofSize: 4}, []byte("short"), 1); !errors.Is(err, ErrInvalidSeed) {
		t.Fatalf("expected invalid seed, got %v", err)
	}
}

func TestFindProofNoSolution(t *testing.T) {
	if _, err := FindProof(Config{EdgeBits: 8, ProofSize: 4}, testSeed(), 0); !errors.Is(err, ErrNoSolution) {
		t.Fatalf("expected no solution, got %v", err)
	}
}

func TestBitsetHelpers(t *testing.T) {
	b := newBitset(130)
	if b.get(65) {
		t.Fatalf("bit should start unset")
	}
	b.set(65)
	if !b.get(65) {
		t.Fatalf("bit should be set")
	}
	b.clear(65)
	if b.get(65) {
		t.Fatalf("bit should be clear")
	}
}

func TestLeafCounterHelpers(t *testing.T) {
	lo := newBitset(8)
	hi := newBitset(8)
	if isLeafCounter(lo, hi, 3) {
		t.Fatalf("empty counter should not be a leaf")
	}
	bumpLeafCounter(lo, hi, 3)
	if !isLeafCounter(lo, hi, 3) {
		t.Fatalf("single edge should be a leaf")
	}
	bumpLeafCounter(lo, hi, 3)
	if isLeafCounter(lo, hi, 3) {
		t.Fatalf("two or more edges should not be a leaf")
	}
	bumpLeafCounter(lo, hi, 3)
	if !hi.get(3) {
		t.Fatalf("counter should stay saturated")
	}
}
