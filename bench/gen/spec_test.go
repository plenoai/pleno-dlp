package main

import (
	"context"
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// memSink collects Finding.Detector for one Emit sequence. Guarded by a
// mutex because Engine.Run dispatches detectors concurrently even for a
// single chunk (see pkg/engine.Options.Concurrency) — go test -race must
// stay clean on this package like every other in the module.
type memSink struct {
	mu   sync.Mutex
	hits []detectors.DetectorType
}

func (s *memSink) Emit(f engine.Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = append(s.hits, f.Detector)
}

func (s *memSink) Close() error { return nil }

func (s *memSink) has(t detectors.DetectorType) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.hits {
		if h == t {
			return true
		}
	}
	return false
}

// TestFixtures_DetectedByPlenoDLP is the adversarial audit this package
// exists to enforce: every fixture in spec.go claims a Detector, and this
// test drives the actual scan engine end to end (prefilter, regex,
// pkg/detectors/all's full registry, and the same placeholder filter the
// CLI installs — see cmd/pleno-dlp/cmd/scan.go's NewPlaceholderFilter
// wiring) to prove the claim holds today. Reusing the real engine instead
// of calling Scanner.FromData directly is deliberate: FromData alone
// would miss both a keyword-prefilter false-negative and a
// placeholder-filter false-positive (the class of bug that produced the
// bogus AKIAIOSFODNN7EXAMPLE "miss" caught while building this
// generator — see bench/README.md).
func TestFixtures_DetectedByPlenoDLP(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 0)) // fixed, independent of the -seed CLI default
	dets := detectors.All()
	if len(dets) == 0 {
		t.Fatal("detectors.All() is empty — pkg/detectors/all did not register anything")
	}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.Slug, func(t *testing.T) {
			content := fx.Render(rng)
			sink := &memSink{}
			audited := engine.NewPlaceholderFilter(sink, nil)
			eng := engine.NewWithDetectors(dets, engine.Options{Concurrency: 4}, audited)

			src := &staticSource{chunks: [][]byte{[]byte(content)}}
			if err := eng.Run(context.Background(), src); err != nil {
				t.Fatalf("engine.Run: %v", err)
			}

			wantHit := knownMisses[fx.Slug] == ""
			gotHit := sink.has(fx.Detector)
			switch {
			case wantHit && !gotHit:
				t.Errorf(
					"fixture %q: expected detectors.%s to fire (post keyword-prefilter, post placeholder-filter) but it did not; other hits: %v\ncontent:\n%s",
					fx.Slug, fx.Detector, sink.hits, content,
				)
			case !wantHit && gotHit:
				t.Errorf(
					"fixture %q: knownMisses says detectors.%s should NOT fire (%s), but it did — update or remove the knownMisses entry",
					fx.Slug, fx.Detector, knownMisses[fx.Slug],
				)
			}
		})
	}
}

// staticSource emits each byte slice as one Chunk. Mirrors the minimal
// fileChunkSource pattern already used by
// pkg/engine/bench_realcorpus_test.go — kept local rather than exported
// from pkg/engine since it's test-only plumbing, not engine surface.
type staticSource struct {
	chunks [][]byte
}

func (s *staticSource) Type() sources.SourceType { return sources.SourceUnknown }

func (s *staticSource) Init(_ context.Context, _ string, _, _ int64, _ bool, _ []byte, _ int) error {
	return nil
}

func (s *staticSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	for _, b := range s.chunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- &sources.Chunk{SourceType: sources.SourceUnknown, SourceName: "bench-gen-test", Data: b}:
		}
	}
	return nil
}
