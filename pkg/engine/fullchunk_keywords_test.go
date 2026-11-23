package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/ahocorasick"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type fullChunkKeywordDet struct{ calls atomic.Int64 }

func (*fullChunkKeywordDet) Type() detectors.DetectorType { return detectors.Pgpass }
func (*fullChunkKeywordDet) Keywords() []string           { return []string{"-", "0"} }
func (*fullChunkKeywordDet) WantsFullChunk() bool         { return true }
func (d *fullChunkKeywordDet) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	d.calls.Add(1)
	return nil, nil
}

// TestFullChunkKeywordsLeaveThePrefilter pins #1015: a FullChunkDetector's
// keywords never dispatch it, so they stay out of the Aho-Corasick set,
// while it still runs once per chunk, with or without a keyword in it.
func TestFullChunkKeywordsLeaveThePrefilter(t *testing.T) {
	t.Parallel()
	full := &fullChunkKeywordDet{}
	window := &stubKeywordDet{}
	e := NewWithDetectors([]detectors.Detector{full, window}, Options{Concurrency: 1, NoVerify: true}, &engineRecordingSink{})
	for _, p := range [][]byte{[]byte("-"), []byte("0")} {
		if prefilterHits(e, p) {
			t.Fatalf("FullChunkDetector keyword %q is in the prefilter", p)
		}
	}
	if !prefilterHits(e, []byte("secret")) {
		t.Fatal("window detector keyword missing from the prefilter")
	}
	for _, data := range []string{"0-0-0", "no keyword here", "a secret"} {
		e.scanChunk(context.Background(), &sources.Chunk{Data: []byte(data)})
	}
	if got := full.calls.Load(); got != 3 {
		t.Fatalf("FullChunkDetector ran %d times, want 3", got)
	}
	if got := window.calls.Load(); got != 1 {
		t.Fatalf("window detector ran %d times, want 1", got)
	}

	onlyFull := NewWithDetectors([]detectors.Detector{&fullChunkKeywordDet{}}, Options{Concurrency: 1, NoVerify: true}, &engineRecordingSink{})
	d := onlyFull.dets[0].(*fullChunkKeywordDet)
	onlyFull.scanChunk(context.Background(), &sources.Chunk{Data: []byte("x")})
	if d.calls.Load() != 1 {
		t.Fatal("an engine of FullChunkDetectors alone must still run them")
	}
}

func prefilterHits(e *Engine, data []byte) bool {
	hit := false
	e.prefilter.VisitHits(data, func(ahocorasick.Hit) { hit = true })
	return hit
}
