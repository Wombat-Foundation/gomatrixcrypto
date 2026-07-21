// Package merkle implements MSC4511 Merkleized event-metadata primitives.
package merkle

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/crypto/sha3"

	"gomatrixlib/matrixjson"
)

const HashSize = 32

var (
	ErrEmptyFieldName = errors.New("merkle: empty field name")
	ErrDuplicateField = errors.New("merkle: duplicate field")
	ErrNoLeaves       = errors.New("merkle: no leaves")
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

// Leaf is a canonical field commitment.
type Leaf struct {
	Name          string
	CanonicalJSON []byte
	Hash          Hash
}

// Header contains the MSC4511 event_header_root fields.
type Header struct {
	RoomID         string
	Sender         string
	Type           string
	StateKey       *string
	Redacts        *string
	Depth          int64
	OriginServerTS int64
}

// LeafHash computes SHA3-256("msc4511:leaf:v1" || field_name || "\x00" ||
// canonical_value).
func LeafHash(fieldName string, canonicalValue []byte) (Hash, error) {
	if fieldName == "" {
		return Hash{}, ErrEmptyFieldName
	}
	return hash(leafDST, []byte(fieldName), []byte{0}, canonicalValue), nil
}

// FieldLeaf canonicalizes and hashes a field value.
func FieldLeaf(field Field) (Leaf, error) {
	if field.Name == "" {
		return Leaf{}, ErrEmptyFieldName
	}
	canonical, err := matrixjson.Canonical(field.Value)
	if err != nil {
		return Leaf{}, err
	}
	h, err := LeafHash(field.Name, canonical)
	if err != nil {
		return Leaf{}, err
	}
	return Leaf{Name: field.Name, CanonicalJSON: canonical, Hash: h}, nil
}

// Leaves canonicalizes fields and returns them sorted bytewise by field name.
func Leaves(fields []Field) ([]Leaf, error) {
	leaves := make([]Leaf, len(fields))
	for i, field := range fields {
		leaf, err := FieldLeaf(field)
		if err != nil {
			return nil, err
		}
		leaves[i] = leaf
	}
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
	leaves, err := Leaves(fields)
	if err != nil {
		return Hash{}, err
	}
	return RootFromLeaves(leaves)
}

// RootFromLeaves computes the RFC 6962 tree shape over already-ordered leaves.
func RootFromLeaves(leaves []Leaf) (Hash, error) {
	if len(leaves) == 0 {
		return Hash{}, ErrNoLeaves
	}
	for i, leaf := range leaves {
		if leaf.Name == "" {
			return Hash{}, ErrEmptyFieldName
		}
		if i > 0 {
			prev := leaves[i-1].Name
			if prev == leaf.Name {
				return Hash{}, fmt.Errorf("%w: %s", ErrDuplicateField, leaf.Name)
			}
			if prev > leaf.Name {
				return Hash{}, errors.New("merkle: leaves not in canonical order")
			}
		}
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
	leaf, err := FieldLeaf(Field{Name: fieldName, Value: value})
	if err != nil {
		return Hash{}, err
	}
	return leaf.Hash, nil
}

// HeaderRoot computes event_header_root over room_id, sender, type, state_key,
// redacts, depth, and origin_server_ts. Missing optional fields are null.
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
		{Name: "sender", Value: header.Sender},
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
