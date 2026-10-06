package merkle

import "testing"

func causalTestKey(b byte) Hash {
	var h Hash
	for i := range h {
		h[i] = b
	}
	return h
}

func TestEmptyCausalSetRootAndCount(t *testing.T) {
	empty := EmptyCausalSet()
	if empty.Count() != 0 {
		t.Fatalf("count = %d, want 0", empty.Count())
	}
	if empty.Root() != causalEmpty[0] {
		t.Fatalf("root = %x, want causalEmpty[0] = %x", empty.Root(), causalEmpty[0])
	}
}

func TestInsertIsIdempotentAndOrderIndependent(t *testing.T) {
	a, b := causalTestKey(0xa1), causalTestKey(0xb2)

	s1 := EmptyCausalSet().Insert(a).Insert(b)
	s2 := EmptyCausalSet().Insert(b).Insert(a)
	s3 := EmptyCausalSet().Insert(a).Insert(b).Insert(a)

	if s1.Root() != s2.Root() || s1.Count() != s2.Count() {
		t.Fatalf("insertion order changed root/count: %x/%d vs %x/%d", s1.Root(), s1.Count(), s2.Root(), s2.Count())
	}
	if s1.Root() != s3.Root() || s3.Count() != 2 {
		t.Fatalf("duplicate insert changed root/count: %x/%d vs %x/%d", s1.Root(), s1.Count(), s3.Root(), s3.Count())
	}
}

func TestUnionEliminatesDuplicates(t *testing.T) {
	a, b, c := causalTestKey(0xa1), causalTestKey(0xb2), causalTestKey(0xc3)

	left := EmptyCausalSet().Insert(a).Insert(b)
	right := EmptyCausalSet().Insert(a).Insert(c)
	union := left.Union(right)

	if union.Count() != 3 {
		t.Fatalf("union count = %d, want 3", union.Count())
	}
	direct := EmptyCausalSet().Insert(a).Insert(b).Insert(c)
	if union.Root() != direct.Root() {
		t.Fatalf("union root %x != direct-insert root %x", union.Root(), direct.Root())
	}
}

func TestContainsInclusionAndNonInclusion(t *testing.T) {
	a, b := causalTestKey(0xa1), causalTestKey(0xb2)
	s := EmptyCausalSet().Insert(a)

	if !s.Contains(a) {
		t.Fatal("expected inclusion for a")
	}
	if s.Contains(b) {
		t.Fatal("expected non-inclusion for b")
	}
}

func TestCausalSetMatchesRecursiveOracle(t *testing.T) {
	keys := make([]Hash, 0, 32)
	for i := 0; i < 32; i++ {
		var k Hash
		k[0] = byte(i * 7)
		k[31] = byte(i*13 + 1)
		keys = append(keys, k)
	}

	set := EmptyCausalSet()
	for _, k := range keys {
		set = set.Insert(k)
	}

	wantRoot, wantCount := causalSubtreeRoot(keys, 0)
	if set.Root() != wantRoot || set.Count() != wantCount {
		t.Fatalf("cached root/count = %x/%d, want %x/%d", set.Root(), set.Count(), wantRoot, wantCount)
	}

	for _, k := range keys {
		path, root, count, ok := set.InclusionProof(k)
		if !ok || root != wantRoot || count != wantCount {
			t.Fatalf("InclusionProof(%x) root/count/ok = %x/%d/%v", k, root, count, ok)
		}
		if !VerifyCausalInclusion(k, path, root, count) {
			t.Fatalf("VerifyCausalInclusion(%x) failed", k)
		}
	}

	var outside Hash
	outside[0] = 0xAA
	if set.Contains(outside) {
		t.Fatal("test key unexpectedly in set")
	}
	path, terminalDepth, root, count, ok := set.NonInclusionProof(outside)
	if !ok || root != wantRoot || count != wantCount {
		t.Fatalf("NonInclusionProof root/count/ok = %x/%d/%v", root, count, ok)
	}
	if !VerifyCausalNonInclusion(terminalDepth, path, root, count) {
		t.Fatal("VerifyCausalNonInclusion failed")
	}
}

func TestSingleMemberRootMatchesLeafConstruction(t *testing.T) {
	a := causalTestKey(0xa1)
	s := EmptyCausalSet().Insert(a)

	want, count := causalSubtreeRoot([]Hash{a}, 0)
	if count != 1 {
		t.Fatalf("count = %d, want 1", count)
	}
	if s.Root() != want {
		t.Fatalf("root = %x, want %x", s.Root(), want)
	}
}
