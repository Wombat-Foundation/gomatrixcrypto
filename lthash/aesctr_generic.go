//go:build !amd64 || purego

package lthash

// aesHardwareExpand reports whether the AES-NI assembly path is available.
// It is only implemented for amd64; other architectures take the crypto/aes
// fallback in expandAES256Element.
func aesHardwareExpand(key *[32]byte, out []byte) bool {
	return false
}
