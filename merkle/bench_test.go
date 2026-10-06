package merkle

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// causalRootSink keeps benchmark results observable so the compiler cannot
// dead-code-eliminate the timed calls.
var causalRootSink Hash

func benchmarkFields(n int) []Field {
	fields := make([]Field, n)
	for i := range fields {
		fields[i] = Field{Name: fmt.Sprintf("field_%03d", i), Value: i}
	}
	return fields
}

func BenchmarkRoot8Fields(b *testing.B) {
	fields := benchmarkFields(8)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Root(fields); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkLeafPath64Fields(b *testing.B) {
	fields := benchmarkFields(64)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, err := LeafPath(fields, "field_032"); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkCausalKeys(n int) []Hash {
	keys := make([]Hash, n)
	for i := range keys {
		var k Hash
		binary.BigEndian.PutUint64(k[24:], uint64(i)+1)
		k[0] = byte(i >> 8)
		k[1] = byte(i)
		keys[i] = k
	}
	return keys
}

func buildCausalSet(keys []Hash) *CausalSet {
	set := EmptyCausalSet()
	for _, k := range keys {
		set = set.Insert(k)
	}
	return set
}

func BenchmarkCausalBuild256(b *testing.B) {
	keys := benchmarkCausalKeys(256)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buildCausalSet(keys)
	}
}

func BenchmarkCausalRoot256(b *testing.B) {
	set := buildCausalSet(benchmarkCausalKeys(256))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		causalRootSink = set.Root()
	}
}

func BenchmarkCausalInclusionProof256(b *testing.B) {
	keys := benchmarkCausalKeys(256)
	set := buildCausalSet(keys)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, ok := set.InclusionProof(keys[i%len(keys)]); !ok {
			b.Fatal("missing inclusion proof")
		}
	}
}
