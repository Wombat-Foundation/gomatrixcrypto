package lthash

import (
	"encoding/binary"
	"testing"

	"github.com/zeebo/blake3"
)

// benchEntry is one representative state element for the insert benchmarks.
var benchEntry = Entry{
	EventType: "m.room.member",
	StateKey:  "@alice:example.org",
	EventID:   "$event-1234567890:example.org",
}

// The sinks keep the accumulators observable so the compiler cannot
// dead-code-eliminate the timed inserts.
var (
	blake3Sink Hash
	aesCTRSink AESCTRHash
)

func BenchmarkBlake3Insert(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		blake3Sink.Insert(benchEntry.EventType, benchEntry.StateKey, benchEntry.EventID)
	}
}

func BenchmarkAESCTRInsert(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aesCTRSink.Insert(benchEntry.EventType, benchEntry.StateKey, benchEntry.EventID)
	}
}

// BenchmarkAESCTRInsertStdlib isolates the portable crypto/aes CTR expansion
// while keeping framing, key derivation, and accumulator work identical.
func BenchmarkAESCTRInsertStdlib(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		xof := blake3.New()
		writeElement(xof, dstAESCTR, benchEntry.EventType, benchEntry.StateKey, benchEntry.EventID)
		var key [32]byte
		_, _ = xof.Digest().Read(key[:])
		var buf [ByteSize]byte
		expandAES256Stdlib(&key, buf[:])
		var seed Hash
		for j := range seed {
			seed[j] = binary.LittleEndian.Uint16(buf[j*2:])
		}
		(*Hash)(&aesCTRSink).addSeed(seed)
	}
}
