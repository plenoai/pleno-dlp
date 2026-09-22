package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"sync/atomic"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/decoder"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

type readerVerificationProbe struct {
	fromData   atomic.Int64
	fromReader atomic.Int64
	verifyArg  atomic.Bool
}

func (*readerVerificationProbe) Type() detectors.DetectorType { return detectors.AWS }

func (*readerVerificationProbe) Keywords() []string { return []string{"reader-verification-token"} }

func (*readerVerificationProbe) WantsFullChunk() bool { return true }

func (*readerVerificationProbe) MaxVerificationAssurance() detectors.VerificationAssurance {
	return detectors.AssuranceProviderConfirmed
}

func (*readerVerificationProbe) Verify(context.Context, string) (bool, error) { return true, nil }

func (p *readerVerificationProbe) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	p.fromData.Add(1)
	return nil, errors.New("reader detector fell back to FromData")
}

func (p *readerVerificationProbe) FromReader(_ context.Context, verify bool, _ io.ReaderAt, _ int64) ([]detectors.Result, error) {
	p.fromReader.Add(1)
	p.verifyArg.Store(verify)
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("reader-verification-token"),
		Verified:     verify,
	}}, nil
}

func TestReaderDetectorPreservesVerificationPolicyAndStats(t *testing.T) {
	tests := []struct {
		name       string
		options    Options
		wantVerify bool
		wantCalls  int64
		wantBypass int64
	}{
		{name: "default", wantVerify: true, wantCalls: 1, wantBypass: 1},
		{name: "no verify", options: Options{NoVerify: true}, wantCalls: 0},
		{
			name:       "minimum assurance",
			options:    Options{MinimumVerificationAssurance: detectors.AssuranceProviderConfirmed},
			wantVerify: true,
			wantCalls:  1,
			wantBypass: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := &readerVerificationProbe{}
			sink := &engineRecordingSink{}
			chunk := &sources.Chunk{
				SourceType: sources.SourceFilesystem,
				Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
					return bytes.NewReader([]byte("reader-verification-token")), io.NopCloser(bytes.NewReader(nil)), int64(len("reader-verification-token")), nil
				},
				SourceMetadata: sources.Metadata{
					Filesystem: &sources.FilesystemMeta{Path: "/fixture/reader-verification.txt", Line: 1},
				},
			}
			eng := NewWithDetectors([]detectors.Detector{probe}, tt.options, sink)
			if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
				t.Fatalf("run: %v", err)
			}
			stats := eng.AggregateStats()
			if probe.fromReader.Load() != 1 || probe.fromData.Load() != 0 {
				t.Fatalf("reader dispatch counts: FromReader=%d FromData=%d", probe.fromReader.Load(), probe.fromData.Load())
			}
			if probe.verifyArg.Load() != tt.wantVerify {
				t.Fatalf("FromReader verify=%v, want %v", probe.verifyArg.Load(), tt.wantVerify)
			}
			if stats.VerifiedDetectorCalls != tt.wantCalls {
				t.Fatalf("verified calls=%d, want %d", stats.VerifiedDetectorCalls, tt.wantCalls)
			}
			if stats.VerificationCacheBypasses != tt.wantBypass {
				t.Fatalf("cache bypasses=%d, want %d", stats.VerificationCacheBypasses, tt.wantBypass)
			}
		})
	}
}

type shortReadAt struct{ data []byte }

func (r shortReadAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, nil
	}
	n := copy(p, r.data[off:])
	return n, nil
}

func TestFindReaderMatchRejectsShortReadWithoutError(t *testing.T) {
	_, _, err := findReaderMatch(context.Background(), shortReadAt{data: []byte("reader-verification-token")}, 64, []byte("reader-verification-token"))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

type recordingCloser struct {
	calls atomic.Int64
	err   error
}

func (c *recordingCloser) Close() error {
	c.calls.Add(1)
	return c.err
}

func TestReaderChunkClosesCloserWhenOpenFails(t *testing.T) {
	openErr := errors.New("deferred open failed")
	closeErr := errors.New("deferred close failed")
	closer := &recordingCloser{err: closeErr}
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceName: "fixture.txt",
		Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			return bytes.NewReader(nil), closer, 0, openErr
		},
	}
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, &engineRecordingSink{})
	_, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}})
	if closer.calls.Load() != 1 {
		t.Fatalf("closer calls=%d, want 1", closer.calls.Load())
	}
	if !errors.Is(err, openErr) || !errors.Is(err, closeErr) {
		t.Fatalf("run error=%v, want opener and closer errors", err)
	}
	var degraded *DegradedError
	if !errors.As(err, &degraded) || degraded.Counts[FailureSource] != 2 {
		t.Fatalf("degradation=%v, want two source failures", err)
	}
}

type normalizedRawDetector struct{}

func (*normalizedRawDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*normalizedRawDetector) Keywords() []string { return []string{"normalized-key"} }

func (*normalizedRawDetector) FromData(context.Context, bool, []byte) ([]detectors.Result, error) {
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("NORMALIZED"),
	}}, nil
}

func runNormalizedRawLine(t *testing.T, data []byte, base int, lazy bool) int {
	t.Helper()
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/fixture/normalized.txt", Line: base},
		},
	}
	if lazy {
		chunk.Open = func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			return bytes.NewReader(data), io.NopCloser(bytes.NewReader(nil)), int64(len(data)), nil
		}
	} else {
		chunk.Data = data
	}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&normalizedRawDetector{}}, Options{Concurrency: 1}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
		t.Fatalf("run lazy=%v base=%d: %v", lazy, base, err)
	}
	findings := sink.Findings()
	if len(findings) != 1 || findings[0].Chunk == nil || findings[0].Chunk.SourceMetadata.Filesystem == nil {
		t.Fatalf("findings lazy=%v base=%d: %#v", lazy, base, findings)
	}
	return findings[0].Chunk.SourceMetadata.Filesystem.Line
}

func TestReaderNormalizedRawPreservesOriginalLineWhenRawIsAbsent(t *testing.T) {
	prefix := bytes.Repeat([]byte("line\n"), windowStepSize/len("line\n")+32)
	data := append(prefix, []byte("normalized-key\n")...)
	for _, base := range []int{1, 0, -2} {
		want := runNormalizedRawLine(t, data, base, false)
		got := runNormalizedRawLine(t, data, base, true)
		if want != base || got != want {
			t.Fatalf("base=%d: buffered line=%d streamed line=%d", base, want, got)
		}
	}
}

type countingReaderAt struct {
	reader io.ReaderAt
	calls  atomic.Int64
	bytes  atomic.Int64
}

func (r *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	r.calls.Add(1)
	r.bytes.Add(int64(len(p)))
	return r.reader.ReadAt(p, off)
}

func TestStreamMatchBatchBoundsDistinctRawReadAmplification(t *testing.T) {
	const (
		size  = 2 << 20
		count = 512
	)
	data := bytes.Repeat([]byte{' '}, size)
	raws := make([][]byte, count+1)
	for i := 0; i < count; i++ {
		raws[i] = []byte(fmt.Sprintf("BATCH_TOKEN_%03d", i))
		copy(data[i*(size/count):], raws[i])
	}
	raws[count] = []byte("BATCH_TOKEN_MISSING")
	reader := &countingReaderAt{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(reader, int64(len(data)))
	if err := cache.resolve(context.Background(), raws, nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if reader.bytes.Load() >= 3<<20 || reader.calls.Load() > 40 {
		t.Fatalf("batched reads: calls=%d bytes=%d, want bounded near one source pass", reader.calls.Load(), reader.bytes.Load())
	}
	t.Logf("batched reads: calls=%d bytes=%d", reader.calls.Load(), reader.bytes.Load())
	for i, raw := range raws[:count] {
		match, ok := cache.lookup(raw)
		want := int64(i * (size / count))
		if !ok || !match.found || match.offset != want {
			t.Fatalf("raw %q = %#v/%v, want offset %d", raw, match, ok, want)
		}
	}
	missing, ok := cache.lookup(raws[count])
	if !ok || missing.found || missing.offset != -1 {
		t.Fatalf("missing raw = %#v/%v, want cached negative result", missing, ok)
	}
	readsAfterFirst := reader.bytes.Load()
	if err := cache.resolve(context.Background(), raws, nil); err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if reader.bytes.Load() != readsAfterFirst {
		t.Fatalf("negative/positive cache was bypassed: bytes before=%d after=%d", readsAfterFirst, reader.bytes.Load())
	}
}

func TestStreamMatchBatchFindsRawAcrossReadBlockBoundary(t *testing.T) {
	const size = 2 * (64 << 10)
	data := bytes.Repeat([]byte("x\n"), size/2)
	raw := []byte("BATCH_BOUNDARY_TOKEN")
	offset := (64 << 10) - 3
	copy(data[offset:], raw)
	reader := bytes.NewReader(data)
	cache := newStreamMatchCache(reader, int64(len(data)))
	if err := cache.resolve(context.Background(), [][]byte{raw}, nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	wantLines := bytes.Count(data[:offset], []byte{'\n'})
	if !ok || !match.found || match.offset != int64(offset) || match.newlineCount != wantLines {
		t.Fatalf("boundary match = %#v/%v, want offset=%d lines=%d", match, ok, offset, wantLines)
	}
}

func TestFindReaderMatchesNarrowsByPrefixAndLength(t *testing.T) {
	// Background repeats 'g.' so the 'g' first byte fires constantly while
	// two-byte and longer prefixes almost never match.
	background := bytes.Repeat([]byte("g."), (64<<10)/2+64)
	raws := [][]byte{
		[]byte("ghp_alpha_token_aaaaaaaaaaaaaaaa"),
		[]byte("ghp_beta_token_bbbbbbbbbbb"),
		[]byte("ghx_mixed_length"),
		[]byte("g"),
		{0x67, 0x00, 0xff, 0x10, 0x77},
		[]byte("ghp_missing_token_zzzzzzzzzzzzzzzz"),
	}
	data := bytes.Clone(background)
	placements := map[string]int64{
		"ghp_alpha_token_aaaaaaaaaaaaaaaa": 5,
		"ghp_beta_token_bbbbbbbbbbb":       (64 << 10) - 4,
		"ghx_mixed_length":                 int64(len(data)) - 20,
		// The 'g.' background already contains 'g' at offset 0, so the
		// single-byte raw's first occurrence is the background's first byte.
		"g": 0,
		string([]byte{0x67, 0x00, 0xff, 0x10, 0x77}): 100,
	}
	for raw, off := range placements {
		copy(data[off:], []byte(raw))
	}
	wanted := make(map[string]struct{}, len(raws))
	for _, raw := range raws {
		wanted[string(raw)] = struct{}{}
	}
	values := make(map[string]streamMatch, len(raws))
	if err := findReaderMatches(context.Background(), bytes.NewReader(data), int64(len(data)), wanted, values); err != nil {
		t.Fatalf("findReaderMatches: %v", err)
	}
	for _, raw := range raws {
		key := string(raw)
		match, ok := values[key]
		if !ok {
			t.Fatalf("raw %q missing from results", key)
		}
		wantOff, placed := placements[key]
		if placed {
			if !match.found || match.offset != wantOff {
				t.Fatalf("raw %q = %#v, want offset %d", key, match, wantOff)
			}
		} else if match.found {
			t.Fatalf("raw %q unexpectedly found at %d", key, match.offset)
		}
	}
}

func TestFindReaderMatchesReturnsFirstOccurrence(t *testing.T) {
	raw := []byte("shared-prefix-token")
	data := bytes.Repeat([]byte("xy\n"), 8<<10)
	first := int64(10)
	second := int64(len(data)) - 30
	copy(data[first:], raw)
	copy(data[second:], raw)
	wanted := map[string]struct{}{string(raw): {}}
	values := make(map[string]streamMatch, 1)
	if err := findReaderMatches(context.Background(), bytes.NewReader(data), int64(len(data)), wanted, values); err != nil {
		t.Fatalf("findReaderMatches: %v", err)
	}
	match := values[string(raw)]
	wantLines := bytes.Count(data[:first], []byte{'\n'})
	if !match.found || match.offset != first || match.newlineCount != wantLines {
		t.Fatalf("first occurrence = %#v, want offset=%d lines=%d", match, first, wantLines)
	}
}

func TestFindReaderMatchesCancellationAndReadError(t *testing.T) {
	readErr := errors.New("reader failed")
	if err := findReaderMatches(context.Background(), failingReaderAt{err: readErr}, 128, map[string]struct{}{"tok": {}}, map[string]streamMatch{}); !errors.Is(err, readErr) {
		t.Fatalf("read error = %v, want %v", err, readErr)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := findReaderMatches(ctx, bytes.NewReader([]byte("tok")), 3, map[string]struct{}{"tok": {}}, map[string]streamMatch{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel error = %v, want %v", err, context.Canceled)
	}
}

type failingReaderAt struct{ err error }

func (r failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func streamBatchTestFinding(line int) Finding {
	return Finding{
		Result: detectors.Result{DetectorType: detectors.AWS, Raw: []byte("batch-partial-token")},
		Chunk: &sources.Chunk{
			SourceType: sources.SourceFilesystem,
			SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{Path: "/fixture/batch.txt", Line: line},
			},
		},
		Detector: detectors.AWS,
	}
}

func TestStreamFindingBatchEmitsFindingWhenSpanReadFails(t *testing.T) {
	readErr := errors.New("span read failed")
	sink := &engineRecordingSink{}
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, sink)
	eng.resetFailures()
	cache := newStreamMatchCache(failingReaderAt{err: readErr}, 1)
	batch := &streamFindingBatch{}
	batch.append(streamBatchTestFinding(3))
	chunk := batch.findings[0].Chunk
	batch.flush(context.Background(), eng, chunk, cache)
	findings := sink.Findings()
	if len(findings) != 1 || string(findings[0].Result.Raw) != "batch-partial-token" || findings[0].RawSpan != nil {
		t.Fatalf("partial findings = %#v, want one unspanned finding", findings)
	}
	var degraded *DegradedError
	if err := eng.takeFailures(); !errors.As(err, &degraded) || !errors.Is(err, readErr) {
		t.Fatalf("span failure = %v, want source degradation wrapping read error", err)
	}
}

func TestStreamFindingBatchEmitsFindingAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sink := &engineRecordingSink{}
	eng := NewWithDetectors(nil, Options{Concurrency: 1}, sink)
	eng.resetFailures()
	cache := newStreamMatchCache(bytes.NewReader([]byte("batch-partial-token")), int64(len("batch-partial-token")))
	batch := &streamFindingBatch{}
	batch.append(streamBatchTestFinding(0))
	chunk := batch.findings[0].Chunk
	batch.flush(ctx, eng, chunk, cache)
	findings := sink.Findings()
	if len(findings) != 1 || findings[0].RawSpan != nil || findings[0].Chunk.SourceMetadata.Filesystem.Line != 0 {
		t.Fatalf("cancelled findings = %#v, want one original-line unspanned finding", findings)
	}
	if err := eng.takeFailures(); err != nil {
		t.Fatalf("cancellation recorded as source failure: %v", err)
	}
}

type windowOwnedRawDetector struct{}

func (*windowOwnedRawDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*windowOwnedRawDetector) Keywords() []string { return []string{"owned-stream-token"} }

func (*windowOwnedRawDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: data}}, nil
}

func TestStreamFindingBatchOwnsWindowRawBeforeFlush(t *testing.T) {
	data := append([]byte("owned-stream-token"), bytes.Repeat([]byte{'x'}, 2*maxWindowSize)...)
	chunk := lazyReaderChunk(data, "/fixture/window-owned.txt")
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&windowOwnedRawDetector{}}, Options{Concurrency: 1}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := sink.Findings()
	if len(findings) != 1 || !bytes.HasPrefix(findings[0].Result.Raw, []byte("owned-stream-token")) {
		t.Fatalf("owned stream raw = %#v, want one token-prefixed finding", findings)
	}
	if findings[0].RawSpan == nil || findings[0].RawSpan[0] != 0 {
		t.Fatalf("owned stream span = %#v, want first source offset", findings[0].RawSpan)
	}
}

func TestStreamFindingBatchOwnsExtraDataBeforeFlush(t *testing.T) {
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&normalizedRawDetector{}}, Options{Concurrency: 1}, sink)
	data := []byte("metadata-token metadata-token")
	cache := newStreamMatchCache(bytes.NewReader(data), int64(len(data)))
	batch := &streamFindingBatch{}
	cache.pending = batch
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/fixture/metadata.txt", Line: 1},
		},
	}
	shared := map[string]string{"marker": "first"}
	result := detectors.Result{
		DetectorType: detectors.AWS,
		Raw:          []byte("metadata-token"),
		ExtraData:    shared,
	}
	eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, result, cache, streamWindowBase{})
	shared["marker"] = "second"
	eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, result, cache, streamWindowBase{})
	cache.pending = nil
	batch.flush(context.Background(), eng, chunk, cache)

	findings := sink.Findings()
	if len(findings) != 2 {
		t.Fatalf("findings=%d, want 2", len(findings))
	}
	if got := findings[0].Result.ExtraData["marker"]; got != "first" {
		t.Fatalf("first ExtraData marker=%q, want first", got)
	}
	if got := findings[1].Result.ExtraData["marker"]; got != "second" {
		t.Fatalf("second ExtraData marker=%q, want second", got)
	}
}

// fanoutRawDetector emits many distinct raws sliced out of its input, so a
// handful of windows produces more findings than one resolution batch can
// hold. Every raw is a verbatim substring of the stream window.
type fanoutRawDetector struct{}

func (*fanoutRawDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*fanoutRawDetector) Keywords() []string { return []string{"kwpair"} }

func (*fanoutRawDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var out []detectors.Result
	for i := 0; i+16 <= len(data) && len(out) < 128; i += 16 {
		out = append(out, detectors.Result{DetectorType: detectors.AWS, Raw: bytes.Clone(data[i : i+16])})
	}
	return out, nil
}

func TestStreamMatchHintBoundsRescanAcrossBatches(t *testing.T) {
	// >1024 hinted raws force several resolution batches. With window hints,
	// position resolution reads only candidate prefix positions, so total
	// reads stay a fraction of one input pass instead of one pass per batch.
	const (
		size      = 2 << 20
		rawCount  = streamFindingBatchLimit + 512
		rawLength = 16
	)
	data := make([]byte, size)
	rand.New(rand.NewSource(1)).Read(data)
	counting := &countingReaderAt{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(counting, int64(size))
	raws := make([][]byte, 0, rawCount)
	hints := make([]streamRawHint, 0, rawCount)
	for start := int64(0); start+rawLength <= int64(size) && len(raws) < rawCount; start += windowStepSize {
		window := data[start:min(start+maxWindowSize, int64(size))]
		cache.observeRawWindow("", window, start)
		for i := 0; i < 64 && len(raws) < rawCount; i++ {
			off := start + int64(i)*512 + 3
			if off+rawLength > start+int64(len(window)) {
				continue
			}
			raws = append(raws, data[off:off+rawLength])
			hints = append(hints, streamRawHint{offset: off, ok: true})
		}
	}
	if len(raws) < rawCount {
		t.Fatalf("built %d raws, want %d", len(raws), rawCount)
	}
	half := len(raws) / 2
	if err := cache.resolve(context.Background(), raws[:half], hints[:half]); err != nil {
		t.Fatalf("first resolve: %v", err)
	}
	if err := cache.resolve(context.Background(), raws[half:], hints[half:]); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if got := counting.bytes.Load(); got > int64(size)/2 {
		t.Fatalf("resolution read %d bytes for input %d, rescan grew with batch count", got, size)
	}
	t.Logf("resolution reads: calls=%d bytes=%d for %d raws", counting.calls.Load(), counting.bytes.Load(), len(raws))
	for i, raw := range raws {
		match, ok := cache.lookup(raw)
		if !ok || !match.found || match.offset != hints[i].offset {
			t.Fatalf("raw %d = %#v/%v, want hinted offset %d", i, match, ok, hints[i].offset)
		}
	}
}

// fixedRawDetector always reports the same raw value regardless of input,
// emulating detectors that normalize before reporting.
type fixedRawDetector struct{ raw []byte }

func (*fixedRawDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*fixedRawDetector) Keywords() []string { return []string{"kwpair2"} }

func (d *fixedRawDetector) FromData(_ context.Context, _ bool, _ []byte) ([]detectors.Result, error) {
	return []detectors.Result{{DetectorType: detectors.AWS, Raw: bytes.Clone(d.raw)}}, nil
}

func TestStreamMatchHintFallsBackToEarlierUndetectedOccurrence(t *testing.T) {
	raw := []byte("shared-early-token")
	data := bytes.Repeat([]byte("filler\n"), 70000/7)
	early := int64(50)
	copy(data[early:], raw)
	late := int64(40 << 10)
	copy(data[late:], "kwpair2 ")
	copy(data[late+8:], raw)
	chunk := lazyReaderChunk(data, "/fixture/hint-early.txt")
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&fixedRawDetector{raw: raw}}, Options{Concurrency: 1}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := sink.Findings()
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range findings {
		if f.RawSpan == nil || int64(f.RawSpan[0]) != early {
			t.Fatalf("span=%v, want first occurrence at %d", f.RawSpan, early)
		}
		wantLine := 1 + bytes.Count(data[:early], []byte{'\n'})
		if got := f.Chunk.SourceMetadata.Filesystem.Line; got != wantLine {
			t.Fatalf("line=%d, want %d", got, wantLine)
		}
	}
}

func TestStreamMatchHintUsedWhenFirstOccurrence(t *testing.T) {
	raw := []byte("hint-first-token")
	data := bytes.Repeat([]byte("pad\n"), 30000)
	at := int64(40 << 10)
	copy(data[at:], "kwpair2 ")
	copy(data[at+8:], raw)
	counting := &countingReaderAt{reader: bytes.NewReader(data)}
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			return counting, io.NopCloser(bytes.NewReader(nil)), int64(len(data)), nil
		},
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/fixture/hint-first.txt", Line: 1},
		},
	}
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&fixedRawDetector{raw: raw}}, Options{Concurrency: 1}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
		t.Fatalf("run: %v", err)
	}
	findings := sink.Findings()
	if len(findings) == 0 {
		t.Fatal("no findings")
	}
	for _, f := range findings {
		if f.RawSpan == nil || int64(f.RawSpan[0]) != at+8 {
			t.Fatalf("span=%v, want hinted occurrence at %d", f.RawSpan, at+8)
		}
	}
	t.Logf("reader calls=%d bytes=%d", counting.calls.Load(), counting.bytes.Load())
}

func TestStreamFindingBatchFlushesAtLimitAndReusesSpanCache(t *testing.T) {
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&normalizedRawDetector{}}, Options{Concurrency: 1}, sink)
	raw := []byte("batch-limit-token")
	cache := newStreamMatchCache(bytes.NewReader(raw), int64(len(raw)))
	batch := &streamFindingBatch{}
	cache.pending = batch
	chunk := &sources.Chunk{SourceType: sources.SourceFilesystem}
	for i := 0; i < streamFindingBatchLimit+1; i++ {
		eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, detectors.Result{
			DetectorType: detectors.AWS,
			Raw:          raw,
		}, cache, streamWindowBase{})
	}
	if got := len(sink.Findings()); got != streamFindingBatchLimit {
		t.Fatalf("findings before final flush=%d, want %d", got, streamFindingBatchLimit)
	}
	cache.pending = nil
	batch.flush(context.Background(), eng, chunk, cache)
	if got := len(sink.Findings()); got != streamFindingBatchLimit+1 {
		t.Fatalf("findings after final flush=%d, want %d", got, streamFindingBatchLimit+1)
	}
}
