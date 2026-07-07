// Real-corpus benchmark wired against /tmp/dlp-bench/corpus-d so we can
// pprof the workload that drove the trufflehog parity push. Skips
// silently when the corpus is absent.
//
// Invoke:
//
//	go test -run=^$ -bench=BenchmarkScan_RealCorpus -benchtime=1x \
//	    -cpuprofile=/tmp/dlp_real.prof ./pkg/engine
//
//go:build realcorpus

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const realCorpusRoot = "/tmp/dlp-bench/corpus-d"

// fileChunkSource walks realCorpusRoot once, emitting every regular
// file's contents as a single Chunk. Mirrors how the filesystem source
// chunks data, minus the cobra-wired glob excludes — keeps the
// benchmark CPU-bound on the engine path.
type fileChunkSource struct {
	root  string
	files [][]byte
}

func (s *fileChunkSource) Type() sources.SourceType { return sources.SourceUnknown }

func (s *fileChunkSource) Init(_ context.Context, _ string, _, _ int64, _ bool, _ []byte, _ int) error {
	if s.files != nil {
		return nil
	}
	return filepath.WalkDir(s.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		if len(b) == 0 {
			return nil
		}
		s.files = append(s.files, b)
		return nil
	})
}

func (s *fileChunkSource) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	for _, b := range s.files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ch <- &sources.Chunk{
			SourceType: sources.SourceUnknown,
			SourceName: "realcorpus",
			Data:       b,
		}:
		}
	}
	return nil
}

func BenchmarkScan_RealCorpus(b *testing.B) {
	if _, err := os.Stat(realCorpusRoot); err != nil {
		b.Skipf("real corpus not present at %s", realCorpusRoot)
	}
	src := &fileChunkSource{root: realCorpusRoot}
	if err := src.Init(context.Background(), "bench", 0, 0, false, nil, 0); err != nil {
		b.Fatalf("Init: %v", err)
	}
	var totalBytes int64
	for _, f := range src.files {
		totalBytes += int64(len(f))
	}
	sink := &nullSink{}
	eng := NewWithDetectors(detectors.All(), Options{Concurrency: 8}, sink)
	b.SetBytes(totalBytes)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := eng.Run(context.Background(), src); err != nil {
			b.Fatalf("Run: %v", err)
		}
	}
}
