// Concurrency benchmarks. These don't run under `go test ./...` —
// invoke explicitly:
//
//	go test ./pkg/engine -run=^$ -bench=BenchmarkScan -benchmem
//
// The benchmarks build a synthetic source with N chunks of M bytes
// each, run the full registered detector set against them, and
// measure throughput. Useful for tuning --concurrency, spotting
// detector regressions, and validating that the keyword prefilter
// stays cheap on the cold path.
package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// benchSource emits a fixed number of chunks of a fixed size on
// Chunks(), then closes. We don't reuse pkg/sources/filesystem here
// to keep the benchmark CPU-bound on the engine path, not on filesystem
// walks.
type benchSource struct {
	chunks   int
	chunkLen int
	template []byte
}

func (b *benchSource) Type() sources.SourceType { return sources.SourceUnknown }

func (b *benchSource) Init(_ context.Context, _ string, _, _ int64, _ bool, _ []byte, _ int) error {
	if b.template == nil {
		// Repeat enough times to overshoot chunkLen, then trim. Computing
		// the repeat count from the line length keeps the slice bounds
		// safe regardless of how the template string changes.
		const line = "a noisy line of plain prose without any credentials\n"
		count := b.chunkLen/len(line) + 2
		b.template = []byte(strings.Repeat(line, count))[:b.chunkLen]
	}
	return nil
}

func (b *benchSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	for i := 0; i < b.chunks; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- &sources.Chunk{
			SourceType: sources.SourceUnknown,
			SourceName: "bench",
			Data:       b.template,
		}:
		}
	}
	return nil
}

// nullSink is a thread-safe no-op for benchmarks. We need
// thread-safety because workers Emit concurrently — a plain
// counter would race the detector.
type nullSink struct {
	mu    sync.Mutex
	count int
}

func (n *nullSink) Emit(Finding) {
	n.mu.Lock()
	n.count++
	n.mu.Unlock()
}
func (n *nullSink) Close() error { return nil }

// BenchmarkScan_ColdPath measures throughput on chunks with no
// matches — every detector runs the keyword prefilter, finds
// nothing, and returns. The number reported is bytes per second per
// worker; that's the dominant cost on real codebases.
func BenchmarkScan_ColdPath(b *testing.B) {
	for _, conc := range []int{1, 4, 8, 16} {
		b.Run(fmt.Sprintf("conc=%d", conc), func(b *testing.B) {
			src := &benchSource{chunks: 1024, chunkLen: 4 * 1024}
			_ = src.Init(context.Background(), "bench", 0, 0, false, nil, 0)
			sink := &nullSink{}
			eng := NewWithDetectors(detectors.All(), Options{Concurrency: conc}, sink)

			b.SetBytes(int64(src.chunks) * int64(src.chunkLen))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := eng.Run(context.Background(), src); err != nil {
					b.Fatalf("Run: %v", err)
				}
			}
			b.StopTimer()
		})
	}
}

// BenchmarkKeywordMatch isolates the prefilter cost — the hottest
// inner loop in the engine. A regression here lights up first
// because every chunk pays this cost, regardless of detector hit
// rate.
//
// Before the Aho-Corasick rewrite this benchmark called keywordMatch
// directly in a per-detector loop. The new shape mirrors the real
// engine path: one lowercase pass per chunk, one AC walk against the
// union of keywords. Reported MB/s should therefore be ~2 orders of
// magnitude higher than the pre-rewrite baseline.
func BenchmarkKeywordMatch(b *testing.B) {
	chunk := []byte(strings.Repeat("This is a noise line that mentions nothing private and no keywords at all.\n", 256))
	eng := NewWithDetectors(detectors.All(), Options{Concurrency: 1}, &nullSink{})
	if eng.prefilter == nil {
		b.Fatalf("expected prefilter to be built")
	}
	lower := make([]byte, 0, len(chunk))
	seen := make([]bool, len(eng.dets))
	out := make([]int32, 0, 16)

	b.SetBytes(int64(len(chunk)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		lower = lowerCaseInto(lower[:0], chunk)
		for j := range seen {
			seen[j] = false
		}
		out = eng.prefilter.MatchInto(lower, seen, out[:0])
	}
	_ = out
}
