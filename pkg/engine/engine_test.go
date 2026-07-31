package engine

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
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

// tokenDet emits one Result whose Raw is a fixed token, so the engine's
// line computation has a concrete offset to locate (unlike stubKeywordDet,
// whose Raw is the whole chunk and always sits at offset 0 / line 1).
type tokenDet struct{ token string }

func (d *tokenDet) Type() detectors.DetectorType { return detectors.AWS }
func (d *tokenDet) Keywords() []string           { return []string{d.token} }
func (d *tokenDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !bytes.Contains(data, []byte(d.token)) {
		return nil, nil
	}
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: []byte(d.token)}}, nil
}

// TestRunReportsMatchLine is the regression test for the "line is always 1"
// bug: a filesystem chunk is a whole file with base line 1, so the finding
// line must be 1 + the number of newlines before the match, not the chunk's
// hardcoded start line.
func TestRunReportsMatchLine(t *testing.T) {
	const token = "AKIA_ON_LINE_FOUR"
	file := "line one\nline two\nline three\n" + token + "\nline five\n"
	src := &stubSource{chunks: []*sources.Chunk{{
		Data:           []byte(file),
		SourceType:     sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: "f.env", Line: 1}},
	}}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&tokenDet{token: token}}, Options{Concurrency: 1}, sink)

	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := sink.Findings()
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1", len(got))
	}
	if line := got[0].Chunk.SourceMetadata.Filesystem.Line; line != 4 {
		t.Errorf("finding line = %d, want 4 (the token is on the 4th line)", line)
	}
	// The shared source chunk must not have been mutated — its base line
	// stays 1 so a second finding on the chunk starts from the right base.
	if base := src.chunks[0].SourceMetadata.Filesystem.Line; base != 1 {
		t.Errorf("source chunk base line mutated to %d, want 1 left intact", base)
	}
}

func TestComputeLineFromMatch(t *testing.T) {
	data := []byte("a\nb\nSECRET\nd\n")
	cases := []struct {
		raw  string
		base int
		want int
	}{
		{"a", 1, 1},
		{"SECRET", 1, 3},
		{"SECRET", 10, 12}, // base offset (git hunk start) is added
		{"absent", 1, 0},   // not found -> 0 (leave line untouched)
		{"", 1, 0},         // empty raw -> 0
	}
	for _, tc := range cases {
		if got := computeLineFromMatch(data, []byte(tc.raw), tc.base); got != tc.want {
			t.Errorf("computeLineFromMatch(%q, base=%d) = %d, want %d", tc.raw, tc.base, got, tc.want)
		}
	}
}

func TestRunWithStats_SequentialReuseReturnsPerRunMetrics(t *testing.T) {
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&stubKeywordDet{}}, Options{Concurrency: 1}, sink)

	first, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("first secret"), SourceType: sources.SourceFilesystem},
	}})
	if err != nil {
		t.Fatalf("first run: %v", err)
	}
	secondData := []byte("second run has no match")
	second, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{
		{Data: secondData, SourceType: sources.SourceFilesystem},
	}})
	if err != nil {
		t.Fatalf("second run: %v", err)
	}

	if first.Chunks != 1 || first.Findings != 1 {
		t.Fatalf("first stats = %+v, want one chunk and finding", first)
	}
	if second.Chunks != 1 || second.Bytes != int64(len(secondData)) || second.Findings != 0 {
		t.Fatalf("second stats = %+v, want metrics isolated from first run", second)
	}
	aggregate := eng.AggregateStats()
	if aggregate.Chunks != 2 || aggregate.Findings != 1 {
		t.Fatalf("aggregate stats = %+v, want both runs", aggregate)
	}
}

type blockingSource struct {
	entered chan<- struct{}
	release <-chan struct{}
}

func (s *blockingSource) Init(context.Context, string, int64, int64, bool, []byte, int) error {
	return nil
}
func (s *blockingSource) Type() sources.SourceType { return sources.SourceFilesystem }
func (s *blockingSource) Chunks(context.Context, chan<- *sources.Chunk) error {
	s.entered <- struct{}{}
	<-s.release
	return nil
}

func TestRunWithStats_ConcurrentReuseIsSerialized(t *testing.T) {
	eng := NewWithDetectors(nil, Options{}, &engineRecordingSink{})
	firstEntered := make(chan struct{}, 1)
	secondEntered := make(chan struct{}, 1)
	firstRelease := make(chan struct{})
	secondRelease := make(chan struct{})
	done := make(chan error, 2)

	go func() {
		_, err := eng.RunWithStats(context.Background(), &blockingSource{firstEntered, firstRelease})
		done <- err
	}()
	<-firstEntered
	go func() {
		_, err := eng.RunWithStats(context.Background(), &blockingSource{secondEntered, secondRelease})
		done <- err
	}()

	// Give the second goroutine repeated opportunities to enter Chunks. It
	// must remain behind the Engine run lock until the first run completes.
	for i := 0; i < 100; i++ {
		runtime.Gosched()
		select {
		case <-secondEntered:
			t.Fatal("concurrent RunWithStats calls entered their sources simultaneously")
		default:
		}
	}
	close(firstRelease)
	<-secondEntered
	close(secondRelease)
	for range 2 {
		if err := <-done; err != nil {
			t.Fatalf("run: %v", err)
		}
	}
}

func TestRunWithStats_QueuedCancellationReturnsWithoutWaiting(t *testing.T) {
	eng := NewWithDetectors(nil, Options{}, &engineRecordingSink{})
	firstEntered := make(chan struct{}, 1)
	firstRelease := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := eng.RunWithStats(context.Background(), &blockingSource{firstEntered, firstRelease})
		firstDone <- err
	}()
	<-firstEntered

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	secondEntered := make(chan struct{}, 1)
	secondRelease := make(chan struct{})
	stats, err := eng.RunWithStats(ctx, &blockingSource{secondEntered, secondRelease})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("queued run error = %v, want context.Canceled", err)
	}
	if stats != (Stats{}) {
		t.Fatalf("queued canceled run stats = %+v, want zero", stats)
	}
	select {
	case <-secondEntered:
		t.Fatal("canceled queued run entered its source")
	default:
	}
	close(firstRelease)
	if err := <-firstDone; err != nil {
		t.Fatalf("first run: %v", err)
	}
}

type verifierPriorityDet struct{}

func (verifierPriorityDet) Type() detectors.DetectorType { return detectors.AWS }
func (verifierPriorityDet) Keywords() []string           { return []string{"collision"} }
func (verifierPriorityDet) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: []byte("shared-secret")}}, nil
}
func (verifierPriorityDet) Verify(context.Context, string) (bool, error) { return true, nil }

type genericCollisionDet struct{}

func (genericCollisionDet) Type() detectors.DetectorType { return detectors.GenericHighEntropy }
func (genericCollisionDet) Keywords() []string           { return []string{"collision"} }
func (genericCollisionDet) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{{DetectorType: detectors.GenericHighEntropy, Raw: []byte("shared-secret")}}, nil
}

func TestEngine_DispatchPreservesVerifierFirstDedupPriority(t *testing.T) {
	for i := 0; i < 100; i++ {
		recorder := &engineRecordingSink{}
		sink := NewDedup(recorder)
		// Supply generic first to prove constructor sorting plus dispatch order,
		// rather than input order, establishes verifier priority.
		eng := NewWithDetectors([]detectors.Detector{genericCollisionDet{}, verifierPriorityDet{}}, Options{Concurrency: 1}, sink)
		_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
			Data: []byte("collision"), SourceType: sources.SourceFilesystem,
		}}})
		if err != nil {
			t.Fatalf("iteration %d: run: %v", i, err)
		}
		got := recorder.Findings()
		if len(got) != 1 || got[0].Detector != detectors.AWS {
			t.Fatalf("iteration %d: findings = %+v, want only verifier-backed AWS", i, got)
		}
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

// indeterminateDet emits a Result with Verified=false and a non-nil
// VerificationErr (Severity left at the zero value) — the shape a real
// detector produces when Verify's HTTP call fails outright rather than
// the provider affirmatively rejecting the secret.
type indeterminateDet struct{}

func (indeterminateDet) Type() detectors.DetectorType { return detectors.AWS }
func (indeterminateDet) Keywords() []string           { return []string{"trigger"} }
func (indeterminateDet) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	return []detectors.Result{{
		DetectorType:    detectors.AWS,
		Raw:             data,
		Verified:        false,
		VerificationErr: errors.New("dial tcp: connection refused"),
	}}, nil
}

// TestEngine_IndeterminateVerdictSeverity pins the severity-mapping choice
// for issue #246: a Result whose verification attempt failed (rather than
// the provider confirming it dead) must default to SeverityCritical, the
// same as a confirmed-live secret — not SeverityHigh, the unverified-AWS
// default. A failed verification attempt doesn't disprove liveness, so
// under-classifying it is the wrong failure mode for a secrets scanner.
func TestEngine_IndeterminateVerdictSeverity(t *testing.T) {
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("trigger me"), SourceType: sources.SourceFilesystem},
	}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{indeterminateDet{}}, Options{}, sink)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	got := sink.Findings()
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Result.Verdict() != detectors.VerdictIndeterminate {
		t.Fatalf("expected VerdictIndeterminate, got %v", got[0].Result.Verdict())
	}
	if got[0].Result.Severity != detectors.SeverityCritical {
		t.Errorf("severity = %v, want SeverityCritical for an indeterminate verdict", got[0].Result.Severity)
	}
}

type assuranceDetector struct {
	max    detectors.VerificationAssurance
	result detectors.Result
}

func (d assuranceDetector) Type() detectors.DetectorType { return detectors.AWS }
func (d assuranceDetector) Keywords() []string           { return []string{"trigger"} }
func (d assuranceDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{d.result}, nil
}
func (d assuranceDetector) MaxVerificationAssurance() detectors.VerificationAssurance {
	return d.max
}

type assuranceExecutionProbe struct {
	max       detectors.VerificationAssurance
	verifyArg atomic.Bool
}

func (d *assuranceExecutionProbe) Type() detectors.DetectorType { return detectors.AWS }
func (d *assuranceExecutionProbe) Keywords() []string           { return []string{"trigger"} }
func (d *assuranceExecutionProbe) Verify(context.Context, string) (bool, error) {
	return true, nil
}
func (d *assuranceExecutionProbe) MaxVerificationAssurance() detectors.VerificationAssurance {
	return d.max
}
func (d *assuranceExecutionProbe) FromData(_ context.Context, verify bool, _ []byte) ([]detectors.Result, error) {
	d.verifyArg.Store(verify)
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("trigger"),
		Verified:     verify,
	}}, nil
}

func runAssuranceTestDetector(t *testing.T, detector detectors.Detector) detectors.Result {
	t.Helper()
	src := &stubSource{chunks: []*sources.Chunk{{
		Data: []byte("trigger"), SourceType: sources.SourceFilesystem,
	}}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{detector}, Options{}, sink)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := sink.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	return findings[0].Result
}

func TestEnginePromotesAuditedVerifiedResultToDeclaredAssurance(t *testing.T) {
	got := runAssuranceTestDetector(t, assuranceDetector{
		max: detectors.AssuranceProviderConfirmed,
		result: detectors.Result{
			DetectorType: detectors.AWS,
			Raw:          []byte("trigger"),
			Verified:     true,
		},
	})
	if got.VerificationAssurance != detectors.AssuranceProviderConfirmed {
		t.Fatalf("assurance = %v, want provider-confirmed", got.VerificationAssurance)
	}
	if !got.Verified {
		t.Fatal("legacy verified verdict must be preserved")
	}
}

func TestEngineRejectsAssuranceAboveDetectorPolicy(t *testing.T) {
	got := runAssuranceTestDetector(t, assuranceDetector{
		max: detectors.AssuranceResponseConfirmed,
		result: detectors.Result{
			DetectorType:          detectors.AWS,
			Raw:                   []byte("trigger"),
			Verified:              true,
			VerificationAssurance: detectors.AssuranceProviderConfirmed,
		},
	})
	if got.Verified {
		t.Fatal("assurance above detector policy must fail closed")
	}
	if got.Verdict() != detectors.VerdictIndeterminate {
		t.Fatalf("verdict = %v, want indeterminate", got.Verdict())
	}
	if got.VerificationAssurance != detectors.AssuranceResponseConfirmed {
		t.Fatalf("assurance = %v, want detector maximum response-confirmed", got.VerificationAssurance)
	}
}

type legacyVerifiedDetector struct{}

func (legacyVerifiedDetector) Type() detectors.DetectorType { return detectors.AWS }
func (legacyVerifiedDetector) Keywords() []string           { return []string{"trigger"} }
func (legacyVerifiedDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("trigger"),
		Verified:     true,
	}}, nil
}

func TestEnginePreservesLegacyVerifiedUnknownAssurance(t *testing.T) {
	got := runAssuranceTestDetector(t, legacyVerifiedDetector{})
	if !got.Verified {
		t.Fatal("legacy verified verdict must remain backward compatible")
	}
	if got.VerificationAssurance != detectors.AssuranceUnknown {
		t.Fatalf("assurance = %v, want unknown", got.VerificationAssurance)
	}
}

func TestEngineMinimumVerificationAssuranceSkipsWeakerVerifier(t *testing.T) {
	detector := &assuranceExecutionProbe{max: detectors.AssuranceResponseConfirmed}
	src := &stubSource{chunks: []*sources.Chunk{{
		Data: []byte("trigger"), SourceType: sources.SourceFilesystem,
	}}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors(
		[]detectors.Detector{detector},
		Options{MinimumVerificationAssurance: detectors.AssuranceProviderConfirmed},
		sink,
	)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if detector.verifyArg.Load() {
		t.Fatal("weaker verifier received verify=true")
	}
	if got := sink.Findings(); len(got) != 1 || got[0].Result.Verified {
		t.Fatalf("findings = %+v, want one unverified candidate", got)
	}
}

func TestEngineMinimumVerificationAssuranceRunsEligibleVerifier(t *testing.T) {
	detector := &assuranceExecutionProbe{max: detectors.AssuranceProviderConfirmed}
	src := &stubSource{chunks: []*sources.Chunk{{
		Data: []byte("trigger"), SourceType: sources.SourceFilesystem,
	}}}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors(
		[]detectors.Detector{detector},
		Options{MinimumVerificationAssurance: detectors.AssuranceProviderConfirmed},
		sink,
	)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !detector.verifyArg.Load() {
		t.Fatal("provider-confirmed verifier received verify=false")
	}
	got := sink.Findings()
	if len(got) != 1 || !got[0].Result.Verified ||
		got[0].Result.VerificationAssurance != detectors.AssuranceProviderConfirmed {
		t.Fatalf("findings = %+v, want one provider-confirmed candidate", got)
	}
}

type failingDet struct{ err error }

func (d failingDet) Type() detectors.DetectorType { return detectors.AWS }
func (d failingDet) Keywords() []string           { return []string{"trigger"} }
func (d failingDet) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return nil, d.err
}

func TestRunWithStats_ReturnsStructuredDetectorDegradation(t *testing.T) {
	wantErr := errors.New("detector crashed")
	eng := NewWithDetectors([]detectors.Detector{failingDet{err: wantErr}}, Options{Concurrency: 1}, &engineRecordingSink{})
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte("trigger"), SourceName: "fixture.txt", SourceType: sources.SourceFilesystem,
	}}})
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("error = %v, want DegradedError", err)
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("error must unwrap detector failure: %v", err)
	}
	if len(degraded.Failures) != 1 {
		t.Fatalf("failures = %+v, want one", degraded.Failures)
	}
	if degraded.Total != 1 || degraded.Counts[FailureDetector] != 1 {
		t.Fatalf("degradation accounting = total %d counts %v", degraded.Total, degraded.Counts)
	}
	failure := degraded.Failures[0]
	if failure.Kind != FailureDetector || failure.Detector != detectors.AWS || failure.Source != "fixture.txt" {
		t.Fatalf("failure = %+v, want structured detector context", failure)
	}
}

func TestRunWithStats_RedactsS3KeyFromDetectorDegradation(t *testing.T) {
	const hostileKey = "credential-like-object-key.txt"
	wantErr := errors.New("detector crashed")
	eng := NewWithDetectors(
		[]detectors.Detector{failingDet{err: wantErr}},
		Options{Concurrency: 1},
		&engineRecordingSink{},
	)
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data:       []byte("trigger"),
		SourceName: "cli",
		SourceType: sources.SourceS3,
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Bucket: "example-bucket", Key: hostileKey},
		},
	}}})
	var degraded *DegradedError
	if !errors.As(err, &degraded) || len(degraded.Failures) != 1 {
		t.Fatalf("error = %#v, want one detector degradation", err)
	}
	failure := degraded.Failures[0]
	if failure.Source != archiveFailureSource(&sources.Chunk{
		SourceMetadata: sources.Metadata{
			S3: &sources.S3Meta{Key: hostileKey},
		},
	}) {
		t.Fatalf("failure source = %q, want hashed S3 identity", failure.Source)
	}
	if strings.Contains(err.Error(), hostileKey) {
		t.Fatalf("detector degradation exposed S3 object key: %q", err)
	}
}

func TestRunWithStats_BoundsDegradationExamples(t *testing.T) {
	const failureCount = maxFailureExamples*4 + 7
	wantErr := errors.New("repeatable detector failure")
	chunks := make([]*sources.Chunk, failureCount)
	for i := range chunks {
		chunks[i] = &sources.Chunk{Data: []byte("trigger"), SourceName: "fixture", SourceType: sources.SourceFilesystem}
	}
	eng := NewWithDetectors([]detectors.Detector{failingDet{err: wantErr}}, Options{Concurrency: 8}, &engineRecordingSink{})
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: chunks})
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("error = %v, want DegradedError", err)
	}
	if degraded.Total != failureCount || degraded.Counts[FailureDetector] != failureCount {
		t.Fatalf("accounting = total %d counts %v, want %d detector failures", degraded.Total, degraded.Counts, failureCount)
	}
	if len(degraded.Failures) != maxFailureExamples {
		t.Fatalf("retained examples = %d, want cap %d", len(degraded.Failures), maxFailureExamples)
	}
	if !errors.Is(err, wantErr) {
		t.Fatal("retained examples must preserve errors.Is for the underlying failure")
	}
}

func TestRunWithStats_ReturnsStructuredArchiveDegradation(t *testing.T) {
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &engineRecordingSink{})
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte{'P', 'K', 3, 4}, SourceName: "broken.zip", SourceType: sources.SourceFilesystem,
	}}})
	var degraded *DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("error = %v, want DegradedError", err)
	}
	if len(degraded.Failures) != 1 || degraded.Failures[0].Kind != FailureArchive || degraded.Failures[0].Source != "broken.zip" {
		t.Fatalf("failures = %+v, want structured archive failure", degraded.Failures)
	}
}

func TestRunWithStats_ArchiveExpansionHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &engineRecordingSink{})
	_, err := eng.RunWithStats(ctx, &stubSource{chunks: []*sources.Chunk{{
		Data: []byte{'P', 'K', 3, 4}, SourceName: "canceled.zip", SourceType: sources.SourceFilesystem,
	}}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestRunWithStats_VerificationFailureIsNotCoverageDegradation(t *testing.T) {
	eng := NewWithDetectors([]detectors.Detector{indeterminateDet{}}, Options{Concurrency: 1}, &engineRecordingSink{})
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{{
		Data: []byte("trigger"), SourceName: "fixture.txt", SourceType: sources.SourceFilesystem,
	}}})
	if err != nil {
		t.Fatalf("VerificationErr belongs to the finding verdict, not scan coverage: %v", err)
	}
}

// verifyArgRecordingDet is a Verifier-implementing detector that records
// the `verify` bool it was actually called with, so tests can assert on
// the engine's dispatch decision directly instead of inferring it from a
// side effect.
type verifyArgRecordingDet struct {
	calls []bool
}

func (d *verifyArgRecordingDet) Type() detectors.DetectorType { return detectors.AWS }
func (d *verifyArgRecordingDet) Keywords() []string           { return []string{"trigger"} }
func (d *verifyArgRecordingDet) FromData(_ context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	d.calls = append(d.calls, verify)
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: data}}, nil
}
func (d *verifyArgRecordingDet) Verify(_ context.Context, _ string) (bool, error) {
	return true, nil
}

// TestEngine_NoVerifyOptionSuppressesVerifyArg is the issue #303 engine-level
// contract test: Options.NoVerify must flip the `verify` bool the engine
// passes into every detector's FromData from the historical unconditional
// true to false. This is the mechanism a fast, offline hook scan relies on
// — without it, --no-verify at the CLI layer would only be able to filter
// verified findings out afterward, not skip the network call that produced
// them.
func TestEngine_NoVerifyOptionSuppressesVerifyArg(t *testing.T) {
	src := &stubSource{chunks: []*sources.Chunk{
		{Data: []byte("trigger me"), SourceType: sources.SourceFilesystem},
	}}

	det := &verifyArgRecordingDet{}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{det}, Options{NoVerify: true}, sink)
	if _, err := eng.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(det.calls) != 1 {
		t.Fatalf("expected exactly 1 FromData call, got %d", len(det.calls))
	}
	if det.calls[0] {
		t.Errorf("NoVerify: true must call FromData with verify=false, got verify=true")
	}

	// An unregistered detector without an explicit cache policy preserves the
	// historical single verified call.
	det2 := &verifyArgRecordingDet{}
	sink2 := &engineRecordingSink{}
	eng2 := NewWithDetectors([]detectors.Detector{det2}, Options{}, sink2)
	if _, err := eng2.RunWithStats(context.Background(), src); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(det2.calls) != 1 || !det2.calls[0] {
		t.Errorf("default Options calls = %v, want [true]", det2.calls)
	}
}
