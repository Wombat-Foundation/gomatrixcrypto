package merkle

import "fmt"

// ProofStep is one sibling hash in a header-tree Merkle path, ordered
// leaf-to-root: applying each step in order (combining the running hash with
// Hash on the named Side) reconstructs the tree root.
type ProofStep struct {
	// Side is "left" or "right": which side Hash sits on relative to the
	// running hash at this step.
	Side string
	// Hash is the sibling hash at this step.
	Hash Hash
}

// FieldLeafHash computes the domain-separated leaf hash for one field. A
// proof verifier recomputes this for each disclosed field before applying
// LeafPath's sibling steps.
func FieldLeafHash(field Field) (Hash, error) {
	l, err := fieldLeaf(field)
	if err != nil {
		return Hash{}, err
	}
	return l.Hash, nil
}

// LeafPath computes the ordered (leaf-to-root) sibling path proving
// fieldName's leaf is included in the RFC 6962-shaped root over fields, along
// with that root. This is the `leaf_paths` construction MSC4511's
// "Cryptographic proof responses" section describes.
func LeafPath(fields []Field, fieldName string) (path []ProofStep, root Hash, err error) {
	ls, err := leaves(fields)
	if err != nil {
		return nil, Hash{}, err
	}
	idx := -1
	for i, l := range ls {
		if l.Name == fieldName {
			idx = i
			break
		}
	}
	if idx < 0 {
		return nil, Hash{}, fmt.Errorf("merkle: field not found: %s", fieldName)
	}
	hashes := make([]Hash, len(ls))
	for i, l := range ls {
		hashes[i] = l.Hash
	}
	root, path = merkleRootAndPath(hashes, idx)
	return path, root, nil
}

// VerifyLeafPath recomputes the root from leafHash and path (leaf-to-root
// ordered siblings) and reports whether it matches root.
func VerifyLeafPath(leafHash Hash, path []ProofStep, root Hash) bool {
	cur := leafHash
	for _, step := range path {
		switch step.Side {
		case "left":
			cur = innerHash(step.Hash, cur)
		case "right":
			cur = innerHash(cur, step.Hash)
		default:
			return false
		}
	}
	return cur == root
}

// merkleRootAndPath computes the RFC 6962 root over hashes and the ordered
// (leaf-to-root) sibling path for hashes[target], mirroring merkleRoot's
// largest-power-of-two split so the two stay consistent.
func merkleRootAndPath(hashes []Hash, target int) (Hash, []ProofStep) {
	switch len(hashes) {
	case 1:
		return hashes[0], nil
	case 2:
		if target == 0 {
			return innerHash(hashes[0], hashes[1]), []ProofStep{{Side: "right", Hash: hashes[1]}}
		}
		return innerHash(hashes[0], hashes[1]), []ProofStep{{Side: "left", Hash: hashes[0]}}
	default:
		k := largestPowerOfTwoLessThan(len(hashes))
		left, right := hashes[:k], hashes[k:]
		if target < k {
			leftRoot, path := merkleRootAndPath(left, target)
			rightRoot := merkleRoot(right)
			return innerHash(leftRoot, rightRoot), append(path, ProofStep{Side: "right", Hash: rightRoot})
		}
		rightRoot, path := merkleRootAndPath(right, target-k)
		leftRoot := merkleRoot(left)
		return innerHash(leftRoot, rightRoot), append(path, ProofStep{Side: "left", Hash: leftRoot})
	}
}
