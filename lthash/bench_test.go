package lthash

import (
	"encoding/binary"
	"testing"
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
		key := aesctrKey(benchEntry.EventType, benchEntry.StateKey, benchEntry.EventID)
		var buf [ByteSize]byte
		expandAES256Stdlib(&key, buf[:])
		var seed Hash
		for j := range seed {
			seed[j] = binary.LittleEndian.Uint16(buf[j*2:])
		}
		(*Hash)(&aesCTRSink).addSeed(seed)
	}
}

var (
	benchKey          [32]byte
	benchBuf          [ByteSize]byte
	checksumBenchSink [ChecksumLen]byte
)

// BenchmarkAES256ExpandStdlib times only the portable crypto/aes expansion.
func BenchmarkAES256ExpandStdlib(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		expandAES256Stdlib(&benchKey, benchBuf[:])
	}
}

// BenchmarkChecksum measures the BLAKE3 collapse over one serialized lattice.
func BenchmarkChecksum(b *testing.B) {
	var state Hash
	for i := range state {
		state[i] = uint16(i * 251)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		checksumBenchSink = state.Checksum()
	}
}
