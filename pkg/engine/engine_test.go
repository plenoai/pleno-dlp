package engine

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// stubSource emits a fixed list of chunks then returns. Used to drive the
// engine without depending on any concrete pkg/sources/* implementation.
type stubSource struct {
	chunks []*sources.Chunk
}

func (s *stubSource) Init(_ context.Context, _ string, _, _ int64, _ bool, _ []byte, _ int) error {
	return nil
}

func (s *stubSource) Chunks(_ context.Context, ch chan<- *sources.Chunk) error {
	for _, c := range s.chunks {
		ch <- c
	}
	return nil
}

func (s *stubSource) Type() sources.SourceType { return sources.SourceFilesystem }

// stubKeywordDet matches every chunk whose data contains "secret" and emits
// one Result. The result count tracks calls so tests can assert downstream
// emission.
type stubKeywordDet struct {
	calls atomic.Int64
}

func (d *stubKeywordDet) Type() detectors.DetectorType { return detectors.AWS }
func (d *stubKeywordDet) Keywords() []string           { return []string{"secret"} }
func (d *stubKeywordDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	d.calls.Add(1)
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: data}}, nil
}

type engineRecordingSink struct {
	findings []Finding
}

func (s *engineRecordingSink) Emit(f Finding) { s.findings = append(s.findings, f) }
func (s *engineRecordingSink) Close() error   { return nil }

func TestRunWithStats_CountsChunksBytesFindings(t *testing.T) {
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("nothing secret here just text"), SourceType: sources.SourceFilesystem},
		{Data: []byte("plain text without keyword"), SourceType: sources.SourceFilesystem},
		{Data: []byte("another secret blob"), SourceType: sources.SourceFilesystem},
	}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&stubKeywordDet{}}, Options{Concurrency: 2}, sink)

	stats, err := eng.RunWithStats(context.Background(), src)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if stats.Chunks != 3 {
		t.Errorf("chunks: want 3, got %d", stats.Chunks)
	}
	wantBytes := int64(len("nothing secret here just text") + len("plain text without keyword") + len("another secret blob"))
	if stats.Bytes != wantBytes {
		t.Errorf("bytes: want %d, got %d", wantBytes, stats.Bytes)
	}
	if stats.Findings != 2 {
		t.Errorf("findings: want 2, got %d", stats.Findings)
	}
	if stats.Duration <= 0 {
		t.Errorf("duration must be positive, got %v", stats.Duration)
	}
	if len(sink.findings) != 2 {
		t.Errorf("sink got %d findings, want 2", len(sink.findings))
	}
}

func TestStatsSnapshot_BeforeRunIsZero(t *testing.T) {
	eng := NewWithDetectors(nil, Options{}, &engineRecordingSink{})
	s := eng.Stats()
	if s.Chunks != 0 || s.Bytes != 0 || s.Findings != 0 {
		t.Errorf("zero engine should report zero stats; got %+v", s)
	}
}
