package merkle

import "testing"

func TestCausalInclusionProofVerifies(t *testing.T) {
	a, b, c := causalTestKey(0xa1), causalTestKey(0xb2), causalTestKey(0xc3)
	s := EmptyCausalSet().Insert(a).Insert(b).Insert(c)

	for _, k := range []Hash{a, b, c} {
		path, root, count, ok := s.InclusionProof(k)
		if !ok {
			t.Fatalf("InclusionProof(%x): expected ok", k)
		}
		if root != s.Root() || count != s.Count() {
			t.Fatalf("InclusionProof(%x) root/count = %x/%d, want %x/%d", k, root, count, s.Root(), s.Count())
		}
		if !VerifyCausalInclusion(k, path, root, count) {
			t.Fatalf("VerifyCausalInclusion(%x) failed", k)
		}
	}
}

func TestCausalInclusionProofRejectsNonMember(t *testing.T) {
	a, d := causalTestKey(0xa1), causalTestKey(0xd4)
	s := EmptyCausalSet().Insert(a)

	if _, _, _, ok := s.InclusionProof(d); ok {
		t.Fatal("expected no inclusion proof for non-member")
	}
}

func TestCausalNonInclusionProofVerifies(t *testing.T) {
	a, b, d := causalTestKey(0xa1), causalTestKey(0xb2), causalTestKey(0xd4)
	s := EmptyCausalSet().Insert(a).Insert(b)

	path, terminalDepth, root, count, ok := s.NonInclusionProof(d)
	if !ok {
		t.Fatal("expected non-inclusion proof for non-member")
	}
	if root != s.Root() || count != s.Count() {
		t.Fatalf("NonInclusionProof root/count = %x/%d, want %x/%d", root, count, s.Root(), s.Count())
	}
	if !VerifyCausalNonInclusion(terminalDepth, path, root, count) {
		t.Fatal("VerifyCausalNonInclusion failed")
	}
}

func TestCausalNonInclusionProofRejectsMember(t *testing.T) {
	a := causalTestKey(0xa1)
	s := EmptyCausalSet().Insert(a)

	if _, _, _, _, ok := s.NonInclusionProof(a); ok {
		t.Fatal("expected no non-inclusion proof for a member")
	}
}

func TestCausalNonInclusionProofOnEmptySet(t *testing.T) {
	d := causalTestKey(0xd4)
	s := EmptyCausalSet()

	path, terminalDepth, root, count, ok := s.NonInclusionProof(d)
	if !ok {
		t.Fatal("expected non-inclusion proof on empty set")
	}
	if len(path) != 0 || terminalDepth != 0 {
		t.Fatalf("path = %v, terminalDepth = %d, want empty path at depth 0", path, terminalDepth)
	}
	if !VerifyCausalNonInclusion(terminalDepth, path, root, count) {
		t.Fatal("VerifyCausalNonInclusion failed on empty set")
	}
}

func TestVerifyCausalInclusionRejectsTamperedSibling(t *testing.T) {
	a, b := causalTestKey(0xa1), causalTestKey(0xb2)
	s := EmptyCausalSet().Insert(a).Insert(b)

	path, root, count, ok := s.InclusionProof(a)
	if !ok {
		t.Fatal("expected inclusion proof")
	}
	if len(path) == 0 {
		t.Fatal("expected non-empty path for a 2-member set")
	}
	path[0].Hash[0] ^= 0xFF
	if VerifyCausalInclusion(a, path, root, count) {
		t.Fatal("tampered sibling should not verify")
	}
}

func TestVerifyCausalNonInclusionRejectsWrongTerminalDepth(t *testing.T) {
	a, b, d := causalTestKey(0xa1), causalTestKey(0xb2), causalTestKey(0xd4)
	s := EmptyCausalSet().Insert(a).Insert(b)

	path, terminalDepth, root, count, ok := s.NonInclusionProof(d)
	if !ok {
		t.Fatal("expected non-inclusion proof")
	}
	if VerifyCausalNonInclusion(terminalDepth+1, path, root, count) {
		t.Fatal("wrong terminal depth should not verify")
	}
}

func TestVerifyCausalNonInclusionRejectsOutOfRangeDepth(t *testing.T) {
	if VerifyCausalNonInclusion(-1, nil, Hash{}, 0) {
		t.Fatal("negative depth should not verify")
	}
	if VerifyCausalNonInclusion(CausalDepth+1, nil, Hash{}, 0) {
		t.Fatal("depth beyond CausalDepth should not verify")
	}
}
