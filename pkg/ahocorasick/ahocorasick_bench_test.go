package ahocorasick

import (
	"strconv"
	"strings"
	"testing"
)

func benchmarkPatterns() [][]byte {
	const (
		prefixes = 256
		base     = "credential detector keyword "
	)
	patterns := make([][]byte, 0, prefixes)
	for i := 0; i < prefixes; i++ {
		patterns = append(patterns, []byte(base+strconv.Itoa(i)+" "))
	}
	return patterns
}

func benchmarkInput() []byte {
	return []byte(strings.Repeat("ordinary source text with no credentials or detector markers; ", 1024))
}

func BenchmarkNew(b *testing.B) {
	patterns := benchmarkPatterns()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = New(patterns)
	}
}

func BenchmarkMatchInto_ColdPath(b *testing.B) {
	m := New(benchmarkPatterns())
	data := benchmarkInput()
	seen := make([]bool, m.NumPatterns())
	out := make([]int32, 0, 8)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := range seen {
			seen[j] = false
		}
		out = m.MatchInto(data, seen, out[:0])
	}
	if len(out) != 0 {
		b.Fatalf("cold benchmark matched %d patterns", len(out))
	}
}

func BenchmarkMatchHitsInto_HotPath(b *testing.B) {
	m := New(benchmarkPatterns())
	data := []byte(strings.Repeat("credential detector keyword 17 ", 1024))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if got := m.MatchHitsInto(data, nil); len(got) == 0 {
			b.Fatal("hot benchmark matched no patterns")
		}
	}
}
