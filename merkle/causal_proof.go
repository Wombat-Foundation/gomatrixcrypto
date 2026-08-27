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
	keys := s.keySlice()
	if len(keys) == 0 {
		return nil, causalEmpty[0], 0, false
	}
	nodeHash, nodeCount, p, kind, _ := causalDescend(keys, 0, key)
	if kind != "leaf" {
		return nil, nodeHash, nodeCount, false
	}
	return p, nodeHash, nodeCount, true
}

// NonInclusionProof returns the ordered (leaf-to-root) sibling path proving
// key is NOT a member of s: the key-directed path terminates in a canonical
// empty subtree at terminalDepth. ok is false if key IS a member (no
// non-inclusion proof exists for a member).
func (s *CausalSet) NonInclusionProof(key Hash) (path []CausalProofStep, terminalDepth int, root Hash, count uint64, ok bool) {
	keys := s.keySlice()
	if len(keys) == 0 {
		return nil, 0, causalEmpty[0], 0, true
	}
	nodeHash, nodeCount, p, kind, tDepth := causalDescend(keys, 0, key)
	if kind != "empty" {
		return nil, 0, nodeHash, nodeCount, false
	}
	return p, tDepth, nodeHash, nodeCount, true
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
		curCount += step.Count
		depth--
	}
	return curHash == root && curCount == count
}

// causalDescend recursively computes the (hash, count) of the subtree over
// keys at depth, plus the ordered leaf-to-root sibling path along target's
// bit-directed descent, stopping early when the descent reaches an empty
// subtree. It returns the terminal node's kind ("leaf" if target was found,
// "empty" if the descent ran out of keys before depth CausalDepth) and the
// depth at which that terminal node sits.
func causalDescend(keys []Hash, depth int, target Hash) (nodeHash Hash, nodeCount uint64, path []CausalProofStep, terminalKind string, terminalDepth int) {
	if len(keys) == 0 {
		return causalEmpty[depth], 0, nil, "empty", depth
	}
	if depth == CausalDepth {
		return causalLeaf(keys[0]), 1, nil, "leaf", depth
	}
	var left, right []Hash
	for _, k := range keys {
		if causalBit(k, depth) == 0 {
			left = append(left, k)
		} else {
			right = append(right, k)
		}
	}
	if causalBit(target, depth) == 0 {
		leftHash, leftCount, leftPath, kind, tDepth := causalDescend(left, depth+1, target)
		rightHash, rightCount := subtreeRootCount(right, depth+1)
		node := causalNode(depth, leftHash, leftCount, rightHash, rightCount)
		path = append(leftPath, CausalProofStep{Side: "right", Hash: rightHash, Count: rightCount})
		return node, leftCount + rightCount, path, kind, tDepth
	}
	rightHash, rightCount, rightPath, kind, tDepth := causalDescend(right, depth+1, target)
	leftHash, leftCount := subtreeRootCount(left, depth+1)
	node := causalNode(depth, leftHash, leftCount, rightHash, rightCount)
	path = append(rightPath, CausalProofStep{Side: "left", Hash: leftHash, Count: leftCount})
	return node, leftCount + rightCount, path, kind, tDepth
}

// subtreeRootCount is causalSubtreeRoot generalized to accept an empty key
// set, returning the canonical empty subtree at depth.
func subtreeRootCount(keys []Hash, depth int) (Hash, uint64) {
	if len(keys) == 0 {
		return causalEmpty[depth], 0
	}
	return causalSubtreeRoot(keys, depth)
}
