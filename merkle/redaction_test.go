package merkle

import "testing"

func TestSplitRedactionContentAllRuleYieldsEmptyEphemeral(t *testing.T) {
	content := map[string]any{"creator": "@alice:example.com", "room_version": "11"}
	redacted, ephemeral := SplitRedactionContent(content, "m.room.create")

	if !deepEqual(redacted, content) {
		t.Fatalf("redacted = %v, want %v", redacted, content)
	}
	if len(ephemeral) != 0 {
		t.Fatalf("ephemeral = %v, want empty", ephemeral)
	}
}

func TestSplitRedactionContentNoneRuleYieldsEmptyRedacted(t *testing.T) {
	content := map[string]any{"body": "hello", "msgtype": "m.text"}
	redacted, ephemeral := SplitRedactionContent(content, "m.room.message")

	if len(redacted) != 0 {
		t.Fatalf("redacted = %v, want empty", redacted)
	}
	if !deepEqual(ephemeral, content) {
		t.Fatalf("ephemeral = %v, want %v", ephemeral, content)
	}
}

func TestSplitRedactionContentKeysRulePartitionsWithoutOverlapOrLoss(t *testing.T) {
	content := map[string]any{"membership": "join", "displayname": "Alice"}
	redacted, ephemeral := SplitRedactionContent(content, "m.room.member")

	wantRedacted := map[string]any{"membership": "join"}
	wantEphemeral := map[string]any{"displayname": "Alice"}
	if !deepEqual(redacted, wantRedacted) {
		t.Fatalf("redacted = %v, want %v", redacted, wantRedacted)
	}
	if !deepEqual(ephemeral, wantEphemeral) {
		t.Fatalf("ephemeral = %v, want %v", ephemeral, wantEphemeral)
	}
}

func TestSplitRedactionContentDottedNestedKeyRemainder(t *testing.T) {
	content := map[string]any{
		"membership": "invite",
		"third_party_invite": map[string]any{
			"signed":       map[string]any{"mxid": "@bob:example.com", "token": "abc"},
			"display_name": "Bob",
		},
	}
	redacted, ephemeral := SplitRedactionContent(content, "m.room.member")

	wantRedactedTPI := map[string]any{"signed": map[string]any{"mxid": "@bob:example.com", "token": "abc"}}
	if !deepEqual(redacted["third_party_invite"], wantRedactedTPI) {
		t.Fatalf("redacted[third_party_invite] = %v, want %v", redacted["third_party_invite"], wantRedactedTPI)
	}
	wantEphemeralTPI := map[string]any{"display_name": "Bob"}
	if !deepEqual(ephemeral["third_party_invite"], wantEphemeralTPI) {
		t.Fatalf("ephemeral[third_party_invite] = %v, want %v", ephemeral["third_party_invite"], wantEphemeralTPI)
	}
}

func TestContentHashCombinesRedactedAndEphemeral(t *testing.T) {
	redacted, err := RedactedContentHash(map[string]any{"membership": "join"})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := EphemeralContentHash(map[string]any{"displayname": "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	otherEphemeral, err := EphemeralContentHash(map[string]any{"displayname": "Bob"})
	if err != nil {
		t.Fatal(err)
	}

	combined := ContentHash(redacted, ephemeral)
	combinedOther := ContentHash(redacted, otherEphemeral)
	if combined == combinedOther {
		t.Fatal("content_hash did not change when ephemeral_content changed")
	}
	if combined != ContentHash(redacted, ephemeral) {
		t.Fatal("content_hash is not deterministic for identical inputs")
	}
}

func TestContentHashSupportsNullEphemeralContent(t *testing.T) {
	redacted, err := RedactedContentHash(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, err := EphemeralContentHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	nullRedacted, err := RedactedContentHash(nil)
	if err != nil {
		t.Fatal(err)
	}

	combined := ContentHash(redacted, ephemeral)
	bothNull := ContentHash(nullRedacted, ephemeral)
	if combined == bothNull {
		t.Fatal("content_hash did not mix in redacted_content_hash")
	}
}
