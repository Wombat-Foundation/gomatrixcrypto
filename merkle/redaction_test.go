package merkle

import "testing"

func TestSplitRedactionContentAllRuleYieldsEmptyRedactable(t *testing.T) {
	content := map[string]any{"creator": "@alice:example.com", "room_version": "11"}
	redacted, redactable := SplitRedactionContent(content, "m.room.create")

	if !deepEqual(redacted, content) {
		t.Fatalf("redacted = %v, want %v", redacted, content)
	}
	if len(redactable) != 0 {
		t.Fatalf("redactable = %v, want empty", redactable)
	}
}

func TestSplitRedactionContentNoneRuleYieldsEmptyRedacted(t *testing.T) {
	content := map[string]any{"body": "hello", "msgtype": "m.text"}
	redacted, redactable := SplitRedactionContent(content, "m.room.message")

	if len(redacted) != 0 {
		t.Fatalf("redacted = %v, want empty", redacted)
	}
	if !deepEqual(redactable, content) {
		t.Fatalf("redactable = %v, want %v", redactable, content)
	}
}

func TestSplitRedactionContentKeysRulePartitionsWithoutOverlapOrLoss(t *testing.T) {
	content := map[string]any{"membership": "join", "displayname": "Alice"}
	redacted, redactable := SplitRedactionContent(content, "m.room.member")

	wantRedacted := map[string]any{"membership": "join"}
	wantRedactable := map[string]any{"displayname": "Alice"}
	if !deepEqual(redacted, wantRedacted) {
		t.Fatalf("redacted = %v, want %v", redacted, wantRedacted)
	}
	if !deepEqual(redactable, wantRedactable) {
		t.Fatalf("redactable = %v, want %v", redactable, wantRedactable)
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
	redacted, redactable := SplitRedactionContent(content, "m.room.member")

	wantRedactedTPI := map[string]any{"signed": map[string]any{"mxid": "@bob:example.com", "token": "abc"}}
	if !deepEqual(redacted["third_party_invite"], wantRedactedTPI) {
		t.Fatalf("redacted[third_party_invite] = %v, want %v", redacted["third_party_invite"], wantRedactedTPI)
	}
	wantRedactableTPI := map[string]any{"display_name": "Bob"}
	if !deepEqual(redactable["third_party_invite"], wantRedactableTPI) {
		t.Fatalf("redactable[third_party_invite] = %v, want %v", redactable["third_party_invite"], wantRedactableTPI)
	}
}

func TestContentHashCombinesRedactedAndRedactable(t *testing.T) {
	redacted, err := RedactedContentHash(map[string]any{"membership": "join"})
	if err != nil {
		t.Fatal(err)
	}
	redactable, err := RedactableContentHash(map[string]any{"displayname": "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	otherRedactable, err := RedactableContentHash(map[string]any{"displayname": "Bob"})
	if err != nil {
		t.Fatal(err)
	}

	combined := ContentHash(redacted, redactable)
	combinedOther := ContentHash(redacted, otherRedactable)
	if combined == combinedOther {
		t.Fatal("content_hash did not change when redactable_content changed")
	}
	if combined != ContentHash(redacted, redactable) {
		t.Fatal("content_hash is not deterministic for identical inputs")
	}
}

func TestContentHashSupportsNullRedactableContent(t *testing.T) {
	redacted, err := RedactedContentHash(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	redactable, err := RedactableContentHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	nullRedacted, err := RedactedContentHash(nil)
	if err != nil {
		t.Fatal(err)
	}

	combined := ContentHash(redacted, redactable)
	bothNull := ContentHash(nullRedacted, redactable)
	if combined == bothNull {
		t.Fatal("content_hash did not mix in redacted_content_hash")
	}
}
