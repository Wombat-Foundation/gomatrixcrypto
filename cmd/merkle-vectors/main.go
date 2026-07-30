// Command merkle-vectors generates stable MSC4511 Merkle vector fixtures.
package main

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/Wombat-Foundation/gomatrixcrypto/merkle"
)

// MerkleVectors is the JSON fixture emitted by the merkle-vectors command.
type MerkleVectors struct {
	// Schema identifies the vector schema version.
	Schema string `json:"schema"`
	// FieldRootHex is the hex-encoded Merkle root of the sample field set.
	FieldRootHex string `json:"field_root_hex"`
	// EventHeaderRootHex is the hex-encoded event_header_root.
	EventHeaderRootHex string `json:"event_header_root_hex"`
	// PrevEventsHashHex is the hex-encoded prev_events component hash.
	PrevEventsHashHex string `json:"prev_events_hash_hex"`
	// AuthEventsHashHex is the hex-encoded auth_events component hash.
	AuthEventsHashHex string `json:"auth_events_hash_hex"`
	// ContentHashHex is the hex-encoded content component hash.
	ContentHashHex string `json:"content_hash_hex"`
	// OtherSignedFieldsHashHex is the hex-encoded other_signed_fields hash.
	OtherSignedFieldsHashHex string `json:"other_signed_fields_hash_hex"`
	// EventRootHex is the hex-encoded top-level event root.
	EventRootHex string `json:"event_root_hex"`
	// EventID is the Matrix event ID derived from EventRootHex.
	EventID string `json:"event_id"`
}

// main is the entry point for the merkle-vectors generator.
func main() {
	output := flag.String("output", "", "optional JSON output file path")
	flag.Parse()

	if err := run(*output); err != nil {
		log.Fatal(err)
	}
}

// run generates Merkle vector test data and writes output.
func run(outputPath string) error {
	fieldRoot, err := merkle.Root(sampleFields())
	if err != nil {
		return err
	}

	headerRoot, err := merkle.HeaderRoot(sampleHeader())
	if err != nil {
		return err
	}

	prevEventsHash, err := merkle.ComponentHash("prev_events", []any{"$a:example.org"})
	if err != nil {
		return err
	}
	authEventsHash, err := merkle.ComponentHash("auth_events", []any{"$auth:example.org"})
	if err != nil {
		return err
	}
	contentHash, err := merkle.ComponentHash("content", map[string]any{"body": "hello", "msgtype": "m.text"})
	if err != nil {
		return err
	}
	otherSignedFieldsHash, err := merkle.ComponentHash("other_signed_fields", map[string]any{"origin": "example.org"})
	if err != nil {
		return err
	}

	eventRoot := merkle.EventRoot(
		prevEventsHash,
		authEventsHash,
		headerRoot,
		contentHash,
		otherSignedFieldsHash,
	)

	vecs := MerkleVectors{
		Schema:                   "msc4511-merkle-vectors-v1",
		FieldRootHex:             hex.EncodeToString(fieldRoot[:]),
		EventHeaderRootHex:       hex.EncodeToString(headerRoot[:]),
		PrevEventsHashHex:        hex.EncodeToString(prevEventsHash[:]),
		AuthEventsHashHex:        hex.EncodeToString(authEventsHash[:]),
		ContentHashHex:           hex.EncodeToString(contentHash[:]),
		OtherSignedFieldsHashHex: hex.EncodeToString(otherSignedFieldsHash[:]),
		EventRootHex:             hex.EncodeToString(eventRoot[:]),
		EventID:                  merkle.EventID(eventRoot),
	}

	fmt.Println("[msc4511-merkle]")
	fmt.Println("field_root_hex =", vecs.FieldRootHex)
	fmt.Println("event_header_root_hex =", vecs.EventHeaderRootHex)
	fmt.Println("prev_events_hash_hex =", vecs.PrevEventsHashHex)
	fmt.Println("auth_events_hash_hex =", vecs.AuthEventsHashHex)
	fmt.Println("content_hash_hex =", vecs.ContentHashHex)
	fmt.Println("other_signed_fields_hash_hex =", vecs.OtherSignedFieldsHashHex)
	fmt.Println("event_root_hex =", vecs.EventRootHex)
	fmt.Println("event_id =", vecs.EventID)

	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
			return err
		}
		data, err := json.MarshalIndent(vecs, "", "  ")
		if err != nil {
			return err
		}
		data = append(data, '\n')
		if err := os.WriteFile(outputPath, data, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", outputPath)
	}

	return nil
}

// sampleFields returns a set of test fields for Merkle tree generation.
func sampleFields() []merkle.Field {
	return []merkle.Field{
		{Name: "depth", Value: int64(7)},
		{Name: "event_id", Value: "$b:example.org"},
		{Name: "prev_events_hash", Value: "sha256:abc"},
		{Name: "rejected", Value: false},
	}
}

// sampleHeader returns a sample event header for testing.
func sampleHeader() merkle.Header {
	return merkle.Header{
		RoomID:          "!room:example.org",
		SenderLocalpart: "alice",
		SenderDomain:    "example.org",
		Type:            "m.room.message",
		Depth:           42,
		OriginServerTS:  123456789,
	}
}
