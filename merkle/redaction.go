package merkle

// RedactionRule describes which content keys a redaction algorithm preserves
// for one event type.
type RedactionRule struct {
	// all, when true, means every content key survives redaction (e.g.
	// m.room.create in room version 11+).
	all bool
	// keys lists the top-level or dotted-path (e.g. "third_party_invite.signed")
	// keys that survive redaction. Ignored when all is true.
	keys []string
}

// RedactionRuleNone preserves nothing: every content key is stripped.
var RedactionRuleNone = RedactionRule{}

// RedactionRuleAll preserves content untouched.
var RedactionRuleAll = RedactionRule{all: true}

// RedactionRuleKeys preserves exactly the listed top-level or dotted-path keys.
func RedactionRuleKeys(keys ...string) RedactionRule {
	return RedactionRule{keys: keys}
}

// RedactionPreservedKeys returns the room-version-11+ content redaction rule
// for eventType. This is the baseline a future room version adopting
// MSC4511's split-canonicalization sketch inherits (room version 12 carries
// v11-redactions verbatim); it deliberately does not model pre-v11 rule
// variants, since a new room version has no reason to resurrect them.
func RedactionPreservedKeys(eventType string) RedactionRule {
	switch eventType {
	case "m.room.create":
		return RedactionRuleAll
	case "m.room.member":
		return RedactionRuleKeys("membership", "join_authorised_via_users_server", "third_party_invite.signed")
	case "m.room.power_levels":
		return RedactionRuleKeys("ban", "events", "events_default", "invite", "kick", "redact", "state_default", "users", "users_default")
	case "m.room.join_rules":
		return RedactionRuleKeys("join_rule", "allow")
	case "m.room.history_visibility":
		return RedactionRuleKeys("history_visibility")
	case "m.room.redaction":
		return RedactionRuleKeys("redacts")
	default:
		return RedactionRuleNone
	}
}

// redactContent filters content down to exactly the keys rule preserves.
// Top-level keys are copied as-is; a dotted path (e.g.
// "third_party_invite.signed") keeps only the nested key under its parent.
func redactContent(content map[string]any, rule RedactionRule) map[string]any {
	if rule.all {
		return cloneMap(content)
	}
	out := map[string]any{}
	for _, path := range rule.keys {
		top, rest, dotted := splitDottedPath(path)
		if !dotted {
			if v, ok := content[top]; ok {
				out[top] = v
			}
			continue
		}
		inner, ok := content[top].(map[string]any)
		if !ok {
			continue
		}
		v, ok := inner[rest]
		if !ok {
			continue
		}
		parent, ok := out[top].(map[string]any)
		if !ok {
			parent = map[string]any{}
			out[top] = parent
		}
		parent[rest] = v
	}
	return out
}

// SplitRedactionContent splits content into MSC4511's redacted_content (the
// fields RedactionPreservedKeys(eventType) preserves) and redactable_content
// (everything redaction strips). redacted and redactable partition content
// without overlap or loss: recombining their keys recovers content's key set.
func SplitRedactionContent(content map[string]any, eventType string) (redacted, redactable map[string]any) {
	rule := RedactionPreservedKeys(eventType)
	redacted = redactContent(content, rule)
	redactable = redactableRemainder(content, redacted)
	return redacted, redactable
}

// redactableRemainder returns the content present in content but not
// preserved in redacted, recursing one level for the
// third_party_invite-shaped nested-path case.
func redactableRemainder(content, redacted map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range content {
		preserved, ok := redacted[key]
		if ok && deepEqual(preserved, value) {
			continue
		}
		preservedInner, preservedIsMap := preserved.(map[string]any)
		fullInner, fullIsMap := value.(map[string]any)
		if ok && preservedIsMap && fullIsMap {
			remainder := map[string]any{}
			for innerKey, innerValue := range fullInner {
				if !deepEqual(preservedInner[innerKey], innerValue) {
					remainder[innerKey] = innerValue
				}
			}
			if len(remainder) > 0 {
				out[key] = remainder
			}
			continue
		}
		out[key] = value
	}
	return out
}

func splitDottedPath(path string) (top, rest string, dotted bool) {
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			return path[:i], path[i+1:], true
		}
	}
	return path, "", false
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func deepEqual(a, b any) bool {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok != bok {
		return false
	}
	if aok {
		if len(am) != len(bm) {
			return false
		}
		for k, av := range am {
			bv, ok := bm[k]
			if !ok || !deepEqual(av, bv) {
				return false
			}
		}
		return true
	}
	return a == b
}
