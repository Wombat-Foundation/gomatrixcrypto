// Command redacted-event-vectors generates a complete, end-to-end MSC4511
// event vector that exercises the redacted/redactable content_hash split
// across a redaction: the same event's event_root and event ID are computed
// before and after redaction and shown to match, using only the retained
// redactable_content_hash after the redactable plaintext is dropped.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/Wombat-Foundation/gomatrixcrypto/merkle"
)

func main() {
	header := merkle.Header{
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.member",
		StateKey:        strPtr("@bob:example.org"),
		Depth:           7,
		OriginServerTS:  1000,
	}
	content := map[string]any{
		"membership": "invite",
		"third_party_invite": map[string]any{
			"signed":       map[string]any{"mxid": "@bob:example.org", "token": "abc"},
			"display_name": "Bob",
		},
	}
	prevEvents := []any{"$a:example.org"}
	authEvents := []any{"$auth:example.org"}
	otherSignedFields := map[string]any{"origin": "example.org"}

	headerRoot, err := merkle.HeaderRoot(header)
	must(err)
	prevEventsHash, err := merkle.ComponentHash("prev_events", prevEvents)
	must(err)
	authEventsHash, err := merkle.ComponentHash("auth_events", authEvents)
	must(err)
	otherSignedFieldsHash, err := merkle.ComponentHash("other_signed_fields", otherSignedFields)
	must(err)

	// --- Before redaction: content_hash over the full content split. ---
	redactedContent, redactableContent := merkle.SplitRedactionContent(content, header.Type)
	redactedContentHash, err := merkle.RedactedContentHash(redactedContent)
	must(err)
	redactableContentHashBefore, err := merkle.RedactableContentHash(redactableContent)
	must(err)
	contentHashBefore := merkle.ContentHash(redactedContentHash, redactableContentHashBefore)
	eventRootBefore := merkle.EventRoot(prevEventsHash, authEventsHash, headerRoot, contentHashBefore, otherSignedFieldsHash)

	// --- After redaction: redactable plaintext is dropped, but the server
	// retains redactableContentHashBefore (a 32-byte value, not the censored
	// display_name) and recomputes the identical content_hash/event_root
	// from redactedContent (still held) plus the retained hash. ---
	retainedRedactableHash := redactableContentHashBefore
	contentHashAfter := merkle.ContentHash(redactedContentHash, retainedRedactableHash)
	eventRootAfter := merkle.EventRoot(prevEventsHash, authEventsHash, headerRoot, contentHashAfter, otherSignedFieldsHash)

	fmt.Println("[msc4511-redacted-event-vector]")
	fmt.Println("event_type =", header.Type)
	fmt.Println("redacted_content =", redactedContent)
	fmt.Println("redactable_content_before_redaction =", redactableContent)
	fmt.Println("redacted_content_hash_hex =", hex.EncodeToString(redactedContentHash[:]))
	fmt.Println("redactable_content_hash_hex =", hex.EncodeToString(redactableContentHashBefore[:]))
	fmt.Println("content_hash_hex =", hex.EncodeToString(contentHashBefore[:]))
	fmt.Println("event_root_before_redaction_hex =", hex.EncodeToString(eventRootBefore[:]))
	fmt.Println("event_id_before_redaction =", merkle.EventID(eventRootBefore))
	fmt.Println("event_root_after_redaction_hex =", hex.EncodeToString(eventRootAfter[:]))
	fmt.Println("event_id_after_redaction =", merkle.EventID(eventRootAfter))
	fmt.Println("event_id_unchanged_by_redaction =", eventRootBefore == eventRootAfter)

	// --- Header leaf proof: disclose sender_domain without sender_localpart. ---
	headerFields := []merkle.Field{
		{Name: "room_id", Value: header.RoomID},
		{Name: "sender_localpart", Value: header.SenderLocalpart},
		{Name: "sender_domain", Value: header.SenderDomain},
		{Name: "type", Value: header.Type},
		{Name: "state_key", Value: *header.StateKey},
		{Name: "redacts", Value: nil},
		{Name: "depth", Value: header.Depth},
		{Name: "origin_server_ts", Value: header.OriginServerTS},
	}
	senderDomainPath, provedHeaderRoot, err := merkle.LeafPath(headerFields, "sender_domain")
	must(err)
	fmt.Println("sender_domain_leaf_path_matches_header_root =", provedHeaderRoot == headerRoot)
	fmt.Println("sender_domain_leaf_path_steps =", len(senderDomainPath))

	// --- Causal set inclusion proof for the event's one prev_events entry. ---
	predecessor := sha3Key("$a:example.org")
	causalSet := merkle.EmptyCausalSet().Insert(predecessor)
	path, root, count, ok := causalSet.InclusionProof(predecessor)
	fmt.Println("causal_inclusion_proof_ok =", ok)
	fmt.Println("causal_inclusion_proof_verifies =", merkle.VerifyCausalInclusion(predecessor, path, root, count))
}

func strPtr(s string) *string { return &s }

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// sha3Key derives a stand-in 32-byte causal-set key from a string, standing
// in for a real event ID's digest.
func sha3Key(s string) merkle.Hash {
	h, err := merkle.ComponentHash("causal_vector_key", s)
	must(err)
	return h
}
