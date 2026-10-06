package merkle

import "encoding/binary"

// CausalDepth is the number of bit-levels in the causal sparse Merkle sum
// trie: one level per bit of a 32-byte (256-bit) event-ID digest key.
const CausalDepth = 256

var (
	causalLeafDST      = []byte("msc4511:causal-leaf:v1")
	causalNodeDST      = []byte("msc4511:causal-node:v1")
	causalEmptyLeafDST = []byte("msc4511:causal-empty-leaf:v1")
)

// causalEmpty[d] is the canonical empty-subtree hash at depth d, for
// d in [0, CausalDepth]. causalEmpty[CausalDepth] is the distinguished empty
// leaf; every other level is derived from causalNode of two empty children.
var causalEmpty = buildCausalEmpty()

func buildCausalEmpty() [CausalDepth + 1]Hash {
	var empty [CausalDepth + 1]Hash
	empty[CausalDepth] = hash(causalEmptyLeafDST)
	for d := CausalDepth - 1; d >= 0; d-- {
		empty[d] = causalNode(d, empty[d+1], 0, empty[d+1], 0)
	}
	return empty
}

// causalLeaf computes SHA3-256("msc4511:causal-leaf:v1" || key).
func causalLeaf(key Hash) Hash {
	return hash(causalLeafDST, key[:])
}

// causalNode computes
// SHA3-256("msc4511:causal-node:v1" || u16be(depth) ||
//
//	left_hash || u64be(left_count) || right_hash || u64be(right_count)).
func causalNode(depth int, leftHash Hash, leftCount uint64, rightHash Hash, rightCount uint64) Hash {
	var depthBuf [2]byte
	binary.BigEndian.PutUint16(depthBuf[:], uint16(depth))
	var leftCountBuf, rightCountBuf [8]byte
	binary.BigEndian.PutUint64(leftCountBuf[:], leftCount)
	binary.BigEndian.PutUint64(rightCountBuf[:], rightCount)
	return hash(causalNodeDST, depthBuf[:], leftHash[:], leftCountBuf[:], rightHash[:], rightCountBuf[:])
}

// causalBit returns the bit of key at depth d (0 = most significant bit of
// byte 0), matching the MSB-to-LSB traversal defined for the causal trie.
func causalBit(key Hash, d int) int {
	byteIdx := d / 8
	bitIdx := 7 - (d % 8)
	return int((key[byteIdx] >> uint(bitIdx)) & 1)
}

// causalTreeNode is one node of the persistent causal trie. A nil node is a
// canonical empty subtree; its hash at depth d is causalEmpty[d]. Non-nil
// nodes cache their subtree's (hash, count) so root and proof construction
// never recompute over the key set.
//
// Nodes are treated as immutable: an insertion rebuilds only the nodes along
// one key's 256-level path and shares every untouched subtree with the prior
// set, so a set is never mutated in place and can be shared freely.
type causalTreeNode struct {
	hash  Hash
	count uint64
	left  *causalTreeNode
	right *causalTreeNode
}

// causalChildHashCount returns the cached (hash, count) of child at depth,
// falling back to the canonical empty subtree when child is nil.
func causalChildHashCount(child *causalTreeNode, depth int) (Hash, uint64) {
	if child == nil {
		return causalEmpty[depth], 0
	}
	return child.hash, child.count
}

// causalInsert returns a new subtree containing node's keys plus key, and
// reports whether key was newly added. It path-copies the O(CausalDepth)
// nodes along key's path and shares all other subtrees with node.
func causalInsert(node *causalTreeNode, depth int, key Hash) (*causalTreeNode, bool) {
	if depth == CausalDepth {
		if node != nil {
			// A 256-bit prefix fully identifies a key, so an occupied leaf
			// here is the same key: a duplicate insert.
			return node, false
		}
		return &causalTreeNode{hash: causalLeaf(key), count: 1}, true
	}

	var left, right *causalTreeNode
	if node != nil {
		left, right = node.left, node.right
	}

	if causalBit(key, depth) == 0 {
		nextLeft, added := causalInsert(left, depth+1, key)
		if !added {
			return node, false
		}
		left = nextLeft
	} else {
		nextRight, added := causalInsert(right, depth+1, key)
		if !added {
			return node, false
		}
		right = nextRight
	}

	leftHash, leftCount := causalChildHashCount(left, depth+1)
	rightHash, rightCount := causalChildHashCount(right, depth+1)
	return &causalTreeNode{
		hash:  causalNode(depth, leftHash, leftCount, rightHash, rightCount),
		count: checkedCountSum(leftCount, rightCount),
		left:  left,
		right: right,
	}, true
}

// CausalSet is an immutable population of event-ID keys committed by a
// persistent 256-level sparse Merkle sum trie, as defined by MSC4511's causal
// sparse Merkle sum trie.
//
// The trie is persistent: mutation returns a new set that shares every
// untouched subtree with the old one, so building an n-key set costs
// O(n · CausalDepth) node allocations and O(1) monotonic memory growth, while
// Root is O(1) and inclusion/non-inclusion proofs are O(CausalDepth).
type CausalSet struct {
	root *causalTreeNode
}

// EmptyCausalSet returns the canonical empty causal set: root causalEmpty[0],
// count 0.
func EmptyCausalSet() *CausalSet {
	return &CausalSet{}
}

// Insert returns a new CausalSet containing every key in s plus key. Insert
// is a no-op (returns an equal set) if key is already a member.
func (s *CausalSet) Insert(key Hash) *CausalSet {
	root, added := causalInsert(s.root, 0, key)
	if !added {
		return s
	}
	return &CausalSet{root: root}
}

// Union returns the set union of s and other, eliminating duplicates, as
// required for a multi-predecessor merge event's causal_set transition.
func (s *CausalSet) Union(other *CausalSet) *CausalSet {
	if other == nil || other.root == nil {
		return s
	}
	if s.root == nil {
		return other
	}
	return &CausalSet{root: causalUnion(s.root, other.root, 0)}
}

// causalUnion structurally merges two subtries. Where one side is the
// canonical empty subtree the other side is shared directly, so the cost is
// proportional to the nodes the two sets do not already share rather than to
// re-hashing every key of one set into the other.
func causalUnion(a, b *causalTreeNode, depth int) *causalTreeNode {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	if a == b {
		return a
	}
	if depth == CausalDepth {
		// A 256-bit prefix identifies one key, so two occupied leaves here
		// are the same key; either node represents it.
		return a
	}
	left := causalUnion(a.left, b.left, depth+1)
	right := causalUnion(a.right, b.right, depth+1)
	leftHash, leftCount := causalChildHashCount(left, depth+1)
	rightHash, rightCount := causalChildHashCount(right, depth+1)
	return &causalTreeNode{
		hash:  causalNode(depth, leftHash, leftCount, rightHash, rightCount),
		count: checkedCountSum(leftCount, rightCount),
		left:  left,
		right: right,
	}
}

// Contains reports whether key is a member of s.
func (s *CausalSet) Contains(key Hash) bool {
	node := s.root
	for depth := 0; depth < CausalDepth; depth++ {
		if node == nil {
			return false
		}
		if causalBit(key, depth) == 0 {
			node = node.left
		} else {
			node = node.right
		}
	}
	return node != nil
}

// Count returns the number of distinct keys committed by s.
func (s *CausalSet) Count() uint64 {
	if s.root == nil {
		return 0
	}
	return s.root.count
}

// Root computes the canonical sparse Merkle sum trie root for s.
func (s *CausalSet) Root() Hash {
	if s.root == nil {
		return causalEmpty[0]
	}
	return s.root.hash
}

// causalSiblingStep packages the sibling subtree child (at depth childDepth)
// as a proof step, falling back to the canonical empty subtree when nil.
func causalSiblingStep(child *causalTreeNode, childDepth int, side string) CausalProofStep {
	hash, count := causalChildHashCount(child, childDepth)
	return CausalProofStep{Side: side, Hash: hash, Count: count}
}

// reverseCausalPath reverses path in place from root-to-leaf to leaf-to-root.
func reverseCausalPath(path []CausalProofStep) {
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
}

// causalSubtreeRoot computes the (hash, count) of the subtree rooted at depth
// that contains exactly the given non-empty key set. It is the recursive
// reference construction; CausalSet maintains the same nodes incrementally.
func causalSubtreeRoot(keys []Hash, depth int) (Hash, uint64) {
	if depth == CausalDepth {
		// Exactly one key must remain: a 256-bit prefix fully identifies a
		// single key.
		return causalLeaf(keys[0]), 1
	}
	var left, right []Hash
	for _, k := range keys {
		if causalBit(k, depth) == 0 {
			left = append(left, k)
		} else {
			right = append(right, k)
		}
	}
	leftHash, leftCount := causalEmpty[depth+1], uint64(0)
	if len(left) > 0 {
		leftHash, leftCount = causalSubtreeRoot(left, depth+1)
	}
	rightHash, rightCount := causalEmpty[depth+1], uint64(0)
	if len(right) > 0 {
		rightHash, rightCount = causalSubtreeRoot(right, depth+1)
	}
	return causalNode(depth, leftHash, leftCount, rightHash, rightCount), checkedCountSum(leftCount, rightCount)
}

// checkedCountSum sums two subtree/sibling counts. The draft's "Room-version
// validity" section mandates rejecting an overflowing count addition rather
// than wrapping or saturating it; this panic is that rejection. In practice a
// real causal set's population is always far below math.MaxUint64, so this
// never actually fires.
func checkedCountSum(a, b uint64) uint64 {
	sum := a + b
	if sum < a {
		panic("msc4511 causal_set count overflow: MUST reject, not wrap or saturate")
	}
	return sum
}
