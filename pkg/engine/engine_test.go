package engine

import (
	"bytes"
	"context"
	"sync"
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

// engineRecordingSink mirrors the production countingSink shape: scan
// workers Emit concurrently from multiple goroutines, so the slice
// append must be lock-protected. Without the mutex, -race fails this
// test intermittently when Engine.opts.Concurrency > 1.
type engineRecordingSink struct {
	mu       sync.Mutex
	findings []Finding
}

func (s *engineRecordingSink) Emit(f Finding) {
	s.mu.Lock()
	s.findings = append(s.findings, f)
	s.mu.Unlock()
}
func (s *engineRecordingSink) Close() error { return nil }
func (s *engineRecordingSink) Findings() []Finding {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

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
	if got := sink.Findings(); len(got) != 2 {
		t.Errorf("sink got %d findings, want 2", len(got))
	}
}

// cancelOnFirstCallDet cancels the scan context the first time it runs,
// then records how many further times FromData is invoked. A correct
// engine checks ctx.Err() at the top of each dispatch loop, so once the
// first call cancels, no further dispatch happens within the same chunk.
type cancelOnFirstCallDet struct {
	cancel     context.CancelFunc
	calls      atomic.Int64
	afterFirst atomic.Int64
}

func (d *cancelOnFirstCallDet) Type() detectors.DetectorType { return detectors.AWS }
func (d *cancelOnFirstCallDet) Keywords() []string           { return []string{"secret"} }
func (d *cancelOnFirstCallDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	n := d.calls.Add(1)
	if n == 1 {
		d.cancel()
		return []detectors.Result{{DetectorType: detectors.AWS, Raw: data}}, nil
	}
	d.afterFirst.Add(1)
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: data}}, nil
}

// TestScan_StopsDispatchingAfterCancel drives a multi-window chunk
// (> maxWindowSize, with a keyword hit in every window) through the
// windowed scan loop. The detector cancels the context on its first
// invocation. Without the ctx.Err() guards in the window/dispatch
// loops the remaining windows keep dispatching the detector; with the
// guards dispatch stops promptly. We assert the post-cancel call count
// is far below the unguarded worst case.
func TestScan_StopsDispatchingAfterCancel(t *testing.T) {
	// Build data spanning many windows, with "secret" near the start of
	// each windowStep so every window produces a keyword hit.
	const windows = 16
	buf := make([]byte, 0, windowStepSize*windows)
	for i := 0; i < windows; i++ {
		seg := bytes.Repeat([]byte("x"), windowStepSize)
		copy(seg, []byte("secret"))
		buf = append(buf, seg...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	det := &cancelOnFirstCallDet{cancel: cancel}
	sink := &engineRecordingSink{}
	// Concurrency 1 so the single chunk is scanned by one worker and the
	// window loop is deterministic.
	eng := NewWithDetectors([]detectors.Detector{det}, Options{Concurrency: 1}, sink)

	src := &stubSource{chunks: []*sources.Chunk{
		{Data: buf, SourceType: sources.SourceFilesystem},
	}}
	if _, err := eng.RunWithStats(ctx, src); err != nil {
		t.Fatalf("run: %v", err)
	}

	after := det.afterFirst.Load()
	// The chunk has >= windows windows. An unguarded loop would call the
	// detector on every one (afterFirst ~ windows-1). With the guard,
	// dispatch stops within the same window's merged spans — at most a
	// couple more calls. Allow a small slack but well below the window
	// count.
	if after > 2 {
		t.Errorf("detector kept dispatching after cancel: afterFirst=%d (want <=2); ctx.Err() guards likely missing", after)
	}
}

func TestStatsSnapshot_BeforeRunIsZero(t *testing.T) {
	eng := NewWithDetectors(nil, Options{}, &engineRecordingSink{})
	s := eng.Stats()
	if s.Chunks != 0 || s.Bytes != 0 || s.Findings != 0 {
		t.Errorf("zero engine should report zero stats; got %+v", s)
	}
}

func TestTagBlastRadius_PromotesAnyMatchingSuffix(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		want bool
	}{
		{"no extra", nil, false},
		{"empty extra", map[string]string{}, false},
		{"unrelated", map[string]string{"decoded_from": "base64"}, false},
		{"privileged", map[string]string{"aws_privileged": "true"}, true},
		{"high_value", map[string]string{"stripe_high_value": "true"}, true},
		{"high_risk", map[string]string{"npm_high_risk": "true"}, true},
		{"value not true", map[string]string{"aws_privileged": "false"}, false},
		{"suffix-but-other-value", map[string]string{"foo_high_risk": "yes"}, false},
		{"multiple flags", map[string]string{
			"slack_privileged":  "true",
			"stripe_high_value": "true",
			"twilio_subaccount": "true",
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &detectors.Result{ExtraData: c.in}
			tagBlastRadius(r)
			got := r.ExtraData["blast_radius"] == "true"
			if got != c.want {
				t.Errorf("blast_radius = %v, want %v (extra=%v)", got, c.want, r.ExtraData)
			}
		})
	}
}

// stubBlastRadiusDet emits a finding with a per-provider blast-radius flag
// in ExtraData. Verifies that the engine post-processes the result and
// rolls the flag up into a stable `blast_radius=true`.
type stubBlastRadiusDet struct{}

func (stubBlastRadiusDet) Type() detectors.DetectorType { return detectors.AWS }
func (stubBlastRadiusDet) Keywords() []string           { return []string{"trigger"} }
func (stubBlastRadiusDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          data,
		Verified:     true,
		ExtraData:    map[string]string{"aws_privileged": "true"},
	}}, nil
}

func TestEngine_StampsBlastRadiusOnEmit(t *testing.T) {
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("trigger me"), SourceType: sources.SourceFilesystem},
	}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{stubBlastRadiusDet{}}, Options{}, sink)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := sink.Findings()
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Result.ExtraData["blast_radius"] != "true" {
		t.Errorf("expected blast_radius=true rolled up from aws_privileged, got %v", got[0].Result.ExtraData)
	}
}
