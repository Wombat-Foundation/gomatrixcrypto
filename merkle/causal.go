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

// CausalSet is an immutable population of event-ID keys committed by a
// persistent 256-level sparse Merkle sum trie, as defined by MSC4511's causal
// sparse Merkle sum trie.
type CausalSet struct {
	keys map[Hash]struct{}
}

// EmptyCausalSet returns the canonical empty causal set: root causalEmpty[0],
// count 0.
func EmptyCausalSet() *CausalSet {
	return &CausalSet{keys: map[Hash]struct{}{}}
}

// Insert returns a new CausalSet containing every key in s plus key. Insert
// is a no-op (returns an equal set) if key is already a member.
func (s *CausalSet) Insert(key Hash) *CausalSet {
	next := make(map[Hash]struct{}, len(s.keys)+1)
	for k := range s.keys {
		next[k] = struct{}{}
	}
	next[key] = struct{}{}
	return &CausalSet{keys: next}
}

// Union returns the set union of s and other, eliminating duplicates, as
// required for a multi-predecessor merge event's causal_set transition.
func (s *CausalSet) Union(other *CausalSet) *CausalSet {
	next := make(map[Hash]struct{}, len(s.keys)+len(other.keys))
	for k := range s.keys {
		next[k] = struct{}{}
	}
	for k := range other.keys {
		next[k] = struct{}{}
	}
	return &CausalSet{keys: next}
}

// Contains reports whether key is a member of s.
func (s *CausalSet) Contains(key Hash) bool {
	_, ok := s.keys[key]
	return ok
}

// Count returns the number of distinct keys committed by s.
func (s *CausalSet) Count() uint64 {
	return uint64(len(s.keys))
}

// Root computes the canonical sparse Merkle sum trie root for s.
func (s *CausalSet) Root() Hash {
	if len(s.keys) == 0 {
		return causalEmpty[0]
	}
	keys := make([]Hash, 0, len(s.keys))
	for k := range s.keys {
		keys = append(keys, k)
	}
	root, _ := causalSubtreeRoot(keys, 0)
	return root
}

// causalSubtreeRoot computes the (hash, count) of the subtree rooted at depth
// that contains exactly the given non-empty key set.
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
	return causalNode(depth, leftHash, leftCount, rightHash, rightCount), leftCount + rightCount
}
