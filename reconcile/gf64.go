// Package reconcile implements MSC0500/MSC0501 set reconciliation helpers.
package reconcile

// Reduction polynomial without its implicit x^64 term.
const reduction uint64 = 0x1b

// MulBitwise performs portable constant-time carry-less multiplication in
// GF(2)[x] / (x^64 + x^4 + x^3 + x + 1).
func MulBitwise(left, right uint64) uint64 {
	var product uint64
	for i := 0; i < 64; i++ {
		product ^= left & (0 - (right & 1))
		right >>= 1

		carry := left >> 63
		left <<= 1
		left ^= reduction & (0 - carry)
	}
	return product
}

// Mul multiplies two elements of the MSC0500 64-bit binary field.
func Mul(left, right uint64) uint64 {
	return MulBitwise(left, right)
}
