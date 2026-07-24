// Package merkle implements MSC4511 Merkleized event-metadata primitives.
package merkle

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/sha3"

	"github.com/Wombat-Foundation/gomatrixcrypto/matrixjson"
)

// HashSize is the byte length of every MSC4511 digest in this package.
const HashSize = 32

var (
	ErrEmptyFieldName   = errors.New("merkle: empty field name")
	ErrInvalidFieldName = errors.New("merkle: invalid field name")
	ErrDuplicateField   = errors.New("merkle: duplicate field")
	ErrNoLeaves         = errors.New("merkle: no leaves")
)

var (
	leafDST = []byte("msc4511:leaf:v1")
	nodeDST = []byte("msc4511:node:v1")
	rootDST = []byte("msc4511:root:v1")
)

// Hash is a SHA3-256 digest.
type Hash [HashSize]byte

// Field is one named metadata value.
//
// Value is encoded with Matrix Canonical JSON before hashing.
type Field struct {
	Name  string
	Value any
}

type leaf struct {
	Name          string
	CanonicalJSON []byte
	Hash          Hash
}

// Header contains the MSC4511 event_header_root fields.
//
// SenderLocalpart and SenderDomain are committed as independent leaves
// (rather than a single combined Sender leaf) so that a proof can disclose
// and verify the sending server's identity without disclosing the sender's
// localpart.
type Header struct {
	RoomID          string
	SenderLocalpart string
	SenderDomain    string
	Type            string
	StateKey        *string
	Redacts         *string
	Depth           int64
	OriginServerTS  int64
}

// leafHash computes SHA3-256("msc4511:leaf:v1" || field_name || "\x00" ||
// canonical_value).
func leafHash(fieldName string, canonicalValue []byte) (Hash, error) {
	if err := validateFieldName(fieldName); err != nil {
		return Hash{}, err
	}
	return hash(leafDST, []byte(fieldName), []byte{0}, canonicalValue), nil
}

// validateFieldName rejects empty names, invalid UTF-8, and embedded NUL
// bytes, which would otherwise collide with the "\x00" delimiter separating
// field_name from canonical_value in leafHash.
func validateFieldName(fieldName string) error {
	if fieldName == "" {
		return ErrEmptyFieldName
	}
	if !utf8.ValidString(fieldName) {
		return ErrInvalidFieldName
	}
	if strings.IndexByte(fieldName, 0) >= 0 {
		return ErrInvalidFieldName
	}
	return nil
}

func fieldLeaf(field Field) (leaf, error) {
	if field.Name == "" {
		return leaf{}, ErrEmptyFieldName
	}
	canonical, err := matrixjson.Canonical(field.Value)
	if err != nil {
		return leaf{}, err
	}
	h, err := leafHash(field.Name, canonical)
	if err != nil {
		return leaf{}, err
	}
	return leaf{Name: field.Name, CanonicalJSON: canonical, Hash: h}, nil
}

func leaves(fields []Field) ([]leaf, error) {
	leaves := make([]leaf, len(fields))
	for i, field := range fields {
		leaf, err := fieldLeaf(field)
		if err != nil {
			return nil, err
		}
		leaves[i] = leaf
	}
	// Go string ordering is bytewise, matching MSC4511's UTF-8 byte ordering
	// after leafHash has rejected malformed field names.
	sort.Slice(leaves, func(i, j int) bool {
		return leaves[i].Name < leaves[j].Name
	})
	for i := 1; i < len(leaves); i++ {
		if leaves[i-1].Name == leaves[i].Name {
			return nil, fmt.Errorf("%w: %s", ErrDuplicateField, leaves[i].Name)
		}
	}
	return leaves, nil
}

// Root computes the RFC 6962 tree shape over field leaves, substituting the
// MSC4511 leaf and inner hash functions. No padding leaves are added.
func Root(fields []Field) (Hash, error) {
	leaves, err := leaves(fields)
	if err != nil {
		return Hash{}, err
	}
	return rootFromLeaves(leaves)
}

func rootFromLeaves(leaves []leaf) (Hash, error) {
	if len(leaves) == 0 {
		return Hash{}, ErrNoLeaves
	}
	hashes := make([]Hash, len(leaves))
	for i, leaf := range leaves {
		hashes[i] = leaf.Hash
	}
	return merkleRoot(hashes), nil
}

// ComponentHash computes one top-level event-root component with the standard
// leaf-hash construction.
func ComponentHash(fieldName string, value any) (Hash, error) {
	leaf, err := fieldLeaf(Field{Name: fieldName, Value: value})
	if err != nil {
		return Hash{}, err
	}
	return leaf.Hash, nil
}

// HeaderRoot computes event_header_root over room_id, sender_localpart,
// sender_domain, type, state_key, redacts, depth, and origin_server_ts.
// Missing optional fields are null. sender_localpart and sender_domain are
// committed as independent leaves so a proof can disclose the sending
// server's identity without disclosing the sender's localpart.
func HeaderRoot(header Header) (Hash, error) {
	var stateKey any
	if header.StateKey != nil {
		stateKey = *header.StateKey
	}
	var redacts any
	if header.Redacts != nil {
		redacts = *header.Redacts
	}
	return Root([]Field{
		{Name: "depth", Value: header.Depth},
		{Name: "origin_server_ts", Value: header.OriginServerTS},
		{Name: "redacts", Value: redacts},
		{Name: "room_id", Value: header.RoomID},
		{Name: "sender_domain", Value: header.SenderDomain},
		{Name: "sender_localpart", Value: header.SenderLocalpart},
		{Name: "state_key", Value: stateKey},
		{Name: "type", Value: header.Type},
	})
}

// EventRoot computes SHA3-256("msc4511:root:v1" || prev_events_hash ||
// auth_events_hash || event_header_root || content_hash ||
// other_signed_fields_hash).
func EventRoot(prevEventsHash, authEventsHash, eventHeaderRoot, contentHash, otherSignedFieldsHash Hash) Hash {
	return hash(rootDST, prevEventsHash[:], authEventsHash[:], eventHeaderRoot[:], contentHash[:], otherSignedFieldsHash[:])
}

// EventID derives "$" || unpadded_base64url(event_root).
func EventID(eventRoot Hash) string {
	return "$" + base64.RawURLEncoding.EncodeToString(eventRoot[:])
}

func merkleRoot(hashes []Hash) Hash {
	switch len(hashes) {
	case 0:
		// Defensive guard only: rootFromLeaves already rejects empty input
		// via ErrNoLeaves, so this has no protocol meaning of its own.
		return Hash{}
	case 1:
		return hashes[0]
	case 2:
		return innerHash(hashes[0], hashes[1])
	default:
		k := largestPowerOfTwoLessThan(len(hashes))
		left := merkleRoot(hashes[:k])
		right := merkleRoot(hashes[k:])
		return innerHash(left, right)
	}
}

func largestPowerOfTwoLessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

func innerHash(left, right Hash) Hash {
	return hash(nodeDST, left[:], right[:])
}

func hash(parts ...[]byte) Hash {
	h := sha3.New256()
	for _, part := range parts {
		h.Write(part)
	}
	var out Hash
	h.Sum(out[:0])
	return out
}
