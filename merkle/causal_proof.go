package merkle

// CausalProofStep is one sibling in a causal sparse Merkle sum trie path,
// ordered leaf-to-root: applying each step in order (combining the running
// hash/count with Hash/Count on the named Side, via causalNode) reconstructs
// the trie root and count.
type CausalProofStep struct {
	// Side is "left" or "right": which side the sibling sits on relative to
	// the running node at this step.
	Side string
	// Hash is the sibling subtree's root hash at this step.
	Hash Hash
	// Count is the sibling subtree's cardinality at this step.
	Count uint64
}

// InclusionProof returns the ordered (leaf-to-root) sibling path proving key
// is a member of s, along with s's root and count. ok is false (path nil) if
// key is not a member; there is no inclusion proof for a non-member.
func (s *CausalSet) InclusionProof(key Hash) (path []CausalProofStep, root Hash, count uint64, ok bool) {
	if s.root == nil {
		return nil, causalEmpty[0], 0, false
	}
	if !s.Contains(key) {
		return nil, s.Root(), s.Count(), false
	}
	path = make([]CausalProofStep, 0, CausalDepth)
	node := s.root
	for d := 0; d < CausalDepth; d++ {
		var left, right *causalTreeNode
		if node != nil {
			left, right = node.left, node.right
		}
		if causalBit(key, d) == 0 {
			path = append(path, causalSiblingStep(right, d+1, "right"))
			node = left
		} else {
			path = append(path, causalSiblingStep(left, d+1, "left"))
			node = right
		}
	}
	reverseCausalPath(path)
	return path, s.Root(), s.Count(), true
}

// NonInclusionProof returns the ordered (leaf-to-root) sibling path proving
// key is NOT a member of s: the key-directed path terminates in a canonical
// empty subtree at terminalDepth. ok is false if key IS a member (no
// non-inclusion proof exists for a member).
func (s *CausalSet) NonInclusionProof(key Hash) (path []CausalProofStep, terminalDepth int, root Hash, count uint64, ok bool) {
	if s.root == nil {
		return nil, 0, causalEmpty[0], 0, true
	}
	if s.Contains(key) {
		return nil, 0, s.Root(), s.Count(), false
	}
	node := s.root
	for d := 0; d < CausalDepth; d++ {
		var left, right *causalTreeNode
		if node != nil {
			left, right = node.left, node.right
		}
		if causalBit(key, d) == 0 {
			path = append(path, causalSiblingStep(right, d+1, "right"))
			node = left
		} else {
			path = append(path, causalSiblingStep(left, d+1, "left"))
			node = right
		}
		if node == nil {
			reverseCausalPath(path)
			return path, d + 1, s.Root(), s.Count(), true
		}
	}
	return nil, 0, s.Root(), s.Count(), false
}

// VerifyCausalInclusion recomputes the root from key's causal_leaf and path
// (leaf-to-root ordered siblings) and reports whether it matches root and
// count.
func VerifyCausalInclusion(key Hash, path []CausalProofStep, root Hash, count uint64) bool {
	return verifyCausalPath(causalLeaf(key), 1, CausalDepth, path, root, count)
}

// VerifyCausalNonInclusion recomputes the root from the canonical empty hash
// at terminalDepth and path (leaf-to-root ordered siblings) and reports
// whether it matches root and count.
func VerifyCausalNonInclusion(terminalDepth int, path []CausalProofStep, root Hash, count uint64) bool {
	if terminalDepth < 0 || terminalDepth > CausalDepth {
		return false
	}
	return verifyCausalPath(causalEmpty[terminalDepth], 0, terminalDepth, path, root, count)
}

// verifyCausalPath recomputes a causal trie root from a terminal node
// (either a causal_leaf and count 1, or a canonical empty hash and count 0)
// by applying path's siblings from the terminal depth up to the root.
// It reports whether both root and count match, returning false for a path
// length mismatch, an invalid sibling side, or a uint64 count overflow.
func verifyCausalPath(terminalHash Hash, terminalCount uint64, terminalDepth int, path []CausalProofStep, root Hash, count uint64) bool {
	if len(path) != terminalDepth {
		return false
	}
	curHash, curCount := terminalHash, terminalCount
	// path is ordered leaf-to-root (deepest sibling first), so depth walks
	// downward from the level just above the terminal node to the root (0).
	depth := terminalDepth - 1
	for _, step := range path {
		switch step.Side {
		case "left":
			curHash = causalNode(depth, step.Hash, step.Count, curHash, curCount)
		case "right":
			curHash = causalNode(depth, curHash, curCount, step.Hash, step.Count)
		default:
			return false
		}
		sum := curCount + step.Count
		if sum < curCount {
			// Overflow of an untrusted count sum: reject rather than panic.
			return false
		}
		curCount = sum
		depth--
	}
	return curHash == root && curCount == count
}
