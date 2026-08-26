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
