package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"gomatrixlib/merkle"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	fmt.Println("[msc4511-merkle]")

	fieldRoot, err := merkle.Root(sampleFields())
	if err != nil {
		return err
	}
	fmt.Println("field_root_hex =", hex.EncodeToString(fieldRoot[:]))

	headerRoot, err := merkle.HeaderRoot(sampleHeader())
	if err != nil {
		return err
	}
	fmt.Println("event_header_root_hex =", hex.EncodeToString(headerRoot[:]))

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

	fmt.Println("prev_events_hash_hex =", hex.EncodeToString(prevEventsHash[:]))
	fmt.Println("auth_events_hash_hex =", hex.EncodeToString(authEventsHash[:]))
	fmt.Println("content_hash_hex =", hex.EncodeToString(contentHash[:]))
	fmt.Println("other_signed_fields_hash_hex =", hex.EncodeToString(otherSignedFieldsHash[:]))

	eventRoot := merkle.EventRoot(
		prevEventsHash,
		authEventsHash,
		headerRoot,
		contentHash,
		otherSignedFieldsHash,
	)
	fmt.Println("event_root_hex =", hex.EncodeToString(eventRoot[:]))
	fmt.Println("event_id =", merkle.EventID(eventRoot))

	return nil
}

func sampleFields() []merkle.Field {
	return []merkle.Field{
		{Name: "depth", Value: int64(7)},
		{Name: "event_id", Value: "$b:example.org"},
		{Name: "prev_events_hash", Value: "sha256:abc"},
		{Name: "rejected", Value: false},
	}
}

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
