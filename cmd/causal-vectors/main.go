// Command causal-vectors generates stable MSC4511 causal sparse Merkle sum
// trie vector fixtures: the empty, single-predecessor, merge-union,
// inclusion, and non-inclusion cases called out as missing from the Part C
// draft's split-canonicalization vectors.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Wombat-Foundation/gomatrixcrypto/merkle"
)

func keyFromEventID(id string) merkle.Hash {
	// Sample keys below are already 32-byte SHA3-256 digests, hex-encoded for
	// readability; real event IDs would hash to these via the room version's
	// event-ID derivation.
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 32 {
		panic("bad sample key: " + id)
	}
	var h merkle.Hash
	copy(h[:], raw)
	return h
}

func main() {
	// Three sample 32-byte digests standing in for event-ID keys A, B, C.
	keyA := keyFromEventID("a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
	keyB := keyFromEventID("b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2")
	keyC := keyFromEventID("c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3")

	fmt.Println("[msc4511-causal-vectors]")

	// Case 1: empty causal set (an event with no prev_events).
	empty := merkle.EmptyCausalSet()
	fmt.Println("empty_root_hex =", hex.EncodeToString(root(empty)))
	fmt.Println("empty_count =", empty.Count())

	// Case 2: single-predecessor (an event with one prev_events entry,
	// inserting that predecessor's event ID into the empty set).
	single := empty.Insert(keyA)
	fmt.Println("single_predecessor_root_hex =", hex.EncodeToString(root(single)))
	fmt.Println("single_predecessor_count =", single.Count())

	// Case 3: merge-union. Two divergent single-predecessor branches (each
	// having inserted its own predecessor ID) are merged; the merge event's
	// causal_set is the exact set union of both populations plus both
	// predecessor IDs, with duplicate elimination (shared keyA is not
	// double-counted).
	branchLeft := empty.Insert(keyA).Insert(keyB)
	branchRight := empty.Insert(keyA).Insert(keyC)
	merged := branchLeft.Union(branchRight)
	fmt.Println("merge_union_root_hex =", hex.EncodeToString(root(merged)))
	fmt.Println("merge_union_count =", merged.Count())

	// Case 4: inclusion. keyB is a member of merged; a responder proves
	// inclusion by exhibiting the key-directed path to a causal_leaf(keyB).
	fmt.Println("inclusion_query_key_hex =", hex.EncodeToString(keyB[:]))
	fmt.Println("inclusion_result =", merged.Contains(keyB))

	// Case 5: non-inclusion. An unrelated key D is not a member of merged; a
	// responder proves non-inclusion by exhibiting a key-directed path that
	// terminates in a canonical empty subtree.
	keyD := keyFromEventID("d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4")
	fmt.Println("non_inclusion_query_key_hex =", hex.EncodeToString(keyD[:]))
	fmt.Println("non_inclusion_result =", merged.Contains(keyD))
}

func root(s *merkle.CausalSet) []byte {
	r := s.Root()
	return r[:]
}
