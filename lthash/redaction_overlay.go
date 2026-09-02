package lthash

import "encoding/base64"

var redactionOverlayDST = []byte("msc4500:redactions:v1")

// RedactionOverlay is the MSC4500 accumulator for selected state events that
// are effectively redacted at a DAG point. It uses the same tuple encoding and
// lattice parameters as Hash, but a separate domain-separation tag.
//
// Callers must maintain set semantics: inserting the same tuple more than
// once intentionally changes the accumulator.
type RedactionOverlay Hash

// Insert adds one effectively redacted selected state event.
func (o *RedactionOverlay) Insert(eventType, stateKey, eventID string) {
	addOverlaySeed(o, seedWithDST(redactionOverlayDST, eventType, stateKey, eventID))
}

// Remove subtracts one previously inserted overlay entry.
func (o *RedactionOverlay) Remove(eventType, stateKey, eventID string) {
	subOverlaySeed(o, seedWithDST(redactionOverlayDST, eventType, stateKey, eventID))
}

// Digest returns the BLAKE2b-256 digest of the overlay lattice.
func (o RedactionOverlay) Digest() [ChecksumLen]byte {
	h := Hash(o)
	return h.Checksum()
}

// String returns the overlay digest as unpadded base64url.
func (o RedactionOverlay) String() string {
	sum := o.Digest()
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func addOverlaySeed(o *RedactionOverlay, seed Hash) {
	for i := range o {
		o[i] += seed[i]
	}
}

func subOverlaySeed(o *RedactionOverlay, seed Hash) {
	for i := range o {
		o[i] -= seed[i]
	}
}
