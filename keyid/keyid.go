// Package keyid derives Matrix FN-DSA key identifiers.
package keyid

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
)

const Context = "matrix:fn-dsa-512:key-id:v1"

// SHA256 derives the canonical full FN-DSA key ID fingerprint.
func SHA256(pub []byte) [sha256.Size]byte {
	var buf [2 + len(Context)]byte
	binary.BigEndian.PutUint16(buf[:2], uint16(len(Context)))
	copy(buf[2:], Context)

	h := sha256.New()
	h.Write(buf[:])
	h.Write(pub)

	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ShortID returns the first 16 base64url characters of the canonical digest.
func ShortID(pub []byte) string {
	sum := SHA256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}
