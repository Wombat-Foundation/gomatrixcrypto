package cuckoo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"time"
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

func TestFindProofCallsOnProgress(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := testSeed()

	var lines []string
	proof, err := FindProof(cfg, seed, 1<<12, func(line string) {
		lines = append(lines, line)
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != cfg.ProofSize {
		t.Fatalf("unexpected proof size: got %d want %d", len(proof), cfg.ProofSize)
	}
	if len(lines) == 0 {
		t.Fatalf("expected onProgress to be called at least once")
	}
}

// FindProof only enters its bulk-trim loop once the live edge count exceeds
// survivorTarget (1<<22). EdgeBits=16 keeps the node space small relative to
// that many edges, so the very first trim round removes nothing and the
// loop exits via its diminishing-returns break rather than the outer
// round-count/target condition, covering both paths in about two seconds.
func TestFindProofEntersBulkTrimLoop(t *testing.T) {
	cfg := Config{EdgeBits: 16, ProofSize: 4}
	seed := testSeed()

	proof, err := FindProof(cfg, seed, (1<<22)+1000)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(cfg, seed, proof); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

// A smaller maxNonce than TestFindProofAndVerify's produces a live-edge set
// with at least one degree-1 node, exercising FindProof's incremental peel
// (which the larger, denser graph in other tests never needs).
func TestFindProofExercisesIncrementalPeel(t *testing.T) {
	cfg := Config{EdgeBits: 8, ProofSize: 4}
	seed := testSeed()

	proof, err := FindProof(cfg, seed, 1<<10)
	if err != nil {
		t.Fatal(err)
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

func TestNormalizeRejectsOutOfRangeProofSize(t *testing.T) {
	if _, err := (Config{EdgeBits: 8, ProofSize: 1}).normalize(); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for too-small ProofSize, got %v", err)
	}
	if _, err := (Config{EdgeBits: 8, ProofSize: 256}).normalize(); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for too-large ProofSize, got %v", err)
	}
}

// The following proofs are hand-picked (via offline brute-force search over
// EdgeForNonce outputs) to exercise cycle-detection branches that a
// tampered-but-otherwise-plausible proof can hit: a nonzero XOR checksum,
// more than one edge sharing a partition value on each side, and no edge at
// all sharing a partition value on the V side. Real proofs from FindProof
// never trigger these, since they only arise from a proof that isn't an
// actual 2-regular cycle in the graph.
func TestVerifyRejectsNonzeroXor(t *testing.T) {
	cfg := Config{EdgeBits: 3, ProofSize: 4}
	if err := Verify(cfg, testSeed(), []uint32{0, 1, 2, 3}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for nonzero xor, got %v", err)
	}
}

func TestVerifyRejectsDuplicateUPartitionMatch(t *testing.T) {
	cfg := Config{EdgeBits: 3, ProofSize: 4}
	if err := Verify(cfg, testSeed(), []uint32{9158, 15434, 17863, 25983}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for duplicate U-partition match, got %v", err)
	}
}

func TestVerifyRejectsDuplicateVPartitionMatch(t *testing.T) {
	cfg := Config{EdgeBits: 3, ProofSize: 4}
	if err := Verify(cfg, testSeed(), []uint32{1644, 13078, 23206, 27540}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for duplicate V-partition match, got %v", err)
	}
}

func TestVerifyRejectsNoVPartitionMatch(t *testing.T) {
	cfg := Config{EdgeBits: 3, ProofSize: 4}
	if err := Verify(cfg, testSeed(), []uint32{14684, 15217, 31161, 31439}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for missing V-partition match, got %v", err)
	}
}

func TestVerifyRejectsSubcycleCountMismatch(t *testing.T) {
	cfg := Config{EdgeBits: 3, ProofSize: 4}
	if err := Verify(cfg, testSeed(), []uint32{989, 8277, 12658, 25760}); !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected invalid proof for a disjoint sub-cycle, got %v", err)
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

func TestTrimAliveEdgesAndCollectSurvivors(t *testing.T) {
	alive := newBitset(4)
	alive.set(0)
	alive.set(1)
	alive.set(2)

	lo := newBitset(5)
	hi := newBitset(5)
	endpoints := func(nonce uint32) (uint64, uint64) {
		switch nonce {
		case 0:
			return 0, 1
		case 1:
			return 0, 1
		case 2:
			return 3, 4
		default:
			return 9, 9
		}
	}

	removed := trimAliveEdges(alive, lo, hi, 4, endpoints)
	if removed != 1 {
		t.Fatalf("expected exactly one edge to be removed, got %d", removed)
	}
	if alive.get(2) {
		t.Fatalf("expected nonce 2 to be cleared")
	}

	survivors := collectSurvivors(alive, 4, endpoints)
	if len(survivors) != 2 {
		t.Fatalf("expected two survivors, got %d", len(survivors))
	}
	if survivors[0].nonce != 0 || survivors[1].nonce != 1 {
		t.Fatalf("unexpected survivors: %#v", survivors)
	}
}

func TestLogDFSProgress(t *testing.T) {
	oldInterval := dfsLogInterval
	dfsLogInterval = 1
	t.Cleanup(func() { dfsLogInterval = oldInterval })

	var lines []string
	log := func(format string, args ...any) {
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	logDFSProgress(0, 10, time.Now(), log)
	if len(lines) != 0 {
		t.Fatalf("unexpected progress log at start edge 0: %v", lines)
	}

	logDFSProgress(1, 10, time.Now(), log)
	if len(lines) != 1 {
		t.Fatalf("expected progress log at start edge 1")
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
