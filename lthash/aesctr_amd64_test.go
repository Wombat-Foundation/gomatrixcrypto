//go:build amd64

package lthash

import "testing"

// TestAES256ForcedFallback exercises the amd64 dispatch with AES-NI disabled.
func TestAES256ForcedFallback(t *testing.T) {
	if !hasAESNI {
		t.Skip("CPU has no AES-NI, so the dispatch fallback is already the default")
	}
	key := seededKey(0xc0ffee)
	var want, got [ByteSize]byte
	expandAES256Stdlib(&key, want[:])

	hasAESNI = false
	t.Cleanup(func() { hasAESNI = true })
	expandAES256Element(&key, got[:])
	if got != want {
		t.Fatalf("dispatched fallback diverges from crypto/aes at byte %d",
			firstDiff(got[:], want[:]))
	}
}

// BenchmarkAES256ExpandHardware isolates AES-NI expansion, including key
// schedule setup, and skips when the current processor cannot run the asm.
func BenchmarkAES256ExpandHardware(b *testing.B) {
	if !hasAESNI {
		b.Skip("CPU has no AES-NI")
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandAES256Element(&benchKey, benchBuf[:])
	}
}
