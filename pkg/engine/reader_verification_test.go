package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
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
	if err := cache.resolve(context.Background(), raws); err != nil {
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
	if err := cache.resolve(context.Background(), raws); err != nil {
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
	if err := cache.resolve(context.Background(), [][]byte{raw}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	wantLines := bytes.Count(data[:offset], []byte{'\n'})
	if !ok || !match.found || match.offset != int64(offset) || match.newlineCount != wantLines {
		t.Fatalf("boundary match = %#v/%v, want offset=%d lines=%d", match, ok, offset, wantLines)
	}
}

type failingReaderAt struct{ err error }

func (r failingReaderAt) ReadAt([]byte, int64) (int, error) { return 0, r.err }

// TestFindReaderMatchesPrefixGroups covers the issue-436 matrix in one
// fixture: a same-(first,length) group whose longest common prefix narrows
// mid-pattern ("gh" for ghp_/gho_ mixes), a first-byte-only group, mixed
// lengths, a 1-byte raw, a binary raw, duplicates (first occurrence wins),
// and an absent raw. newlineCount must match a whole-input count.
func TestFindReaderMatchesPrefixGroups(t *testing.T) {
	data := bytes.Repeat([]byte("g."), 4<<10)
	data = append(data, '\n')
	plants := map[string]int64{}
	put := func(raw string) {
		plants[raw] = int64(len(data))
		data = append(data, raw...)
		data = append(data, bytes.Repeat([]byte("g."), 64)...)
	}
	put("ghp_tokenaaaa")
	put("ghp_tokenbbbb")
	put("gho_tokencccc")
	put("z")
	put("\x00\xff\x00\x80")
	put("a_much_longer_raw_value_here")
	put("dup_token")
	// The same raw planted a second time must not displace the first.
	data = append(data, "dup_token"...)
	data = append(data, bytes.Repeat([]byte("g."), 64)...)

	wanted := map[string]struct{}{}
	for raw := range plants {
		wanted[raw] = struct{}{}
	}
	wanted["ghp_missing"] = struct{}{}

	values := make(map[string]streamMatch)
	if err := findReaderMatches(context.Background(), bytes.NewReader(data), int64(len(data)), wanted, values); err != nil {
		t.Fatalf("findReaderMatches: %v", err)
	}
	for raw, offset := range plants {
		match, ok := values[raw]
		wantLines := bytes.Count(data[:offset], []byte{'\n'})
		if !ok || !match.found || match.offset != offset || match.newlineCount != wantLines {
			t.Fatalf("raw %q = %#v/%v, want offset=%d lines=%d", raw, match, ok, offset, wantLines)
		}
	}
	if missing := values["ghp_missing"]; missing.found || missing.offset != -1 {
		t.Fatalf("missing raw = %#v, want unfound", missing)
	}
}

// TestFindReaderMatchesPrefixAcrossBlockBoundary keeps the 64 KiB read
// boundary honest for the prefix path: a grouped pattern spanning the block
// split must still resolve through the overlap.
func TestFindReaderMatchesPrefixAcrossBlockBoundary(t *testing.T) {
	data := bytes.Repeat([]byte("gh"), 40<<10)
	raws := [][]byte{[]byte("ghp_boundaryaaaa"), []byte("ghp_boundarybbbb")}
	offset := (64 << 10) - 5
	copy(data[offset:], raws[0])
	copy(data[offset+64:], raws[1])
	wanted := map[string]struct{}{string(raws[0]): {}, string(raws[1]): {}}
	values := make(map[string]streamMatch)
	if err := findReaderMatches(context.Background(), bytes.NewReader(data), int64(len(data)), wanted, values); err != nil {
		t.Fatalf("findReaderMatches: %v", err)
	}
	for i, want := range []int64{int64(offset), int64(offset + 64)} {
		match := values[string(raws[i])]
		if !match.found || match.offset != want {
			t.Fatalf("boundary raw %d = %#v, want offset %d", i, match, want)
		}
	}
}

func TestFindReaderMatchesCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	data := bytes.Repeat([]byte("g."), 4<<10)
	wanted := map[string]struct{}{"ghp_token": {}}
	values := make(map[string]streamMatch)
	if err := findReaderMatches(ctx, bytes.NewReader(data), int64(len(data)), wanted, values); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan err=%v, want context.Canceled", err)
	}
}

func TestFindReaderMatchesReadErrorPropagates(t *testing.T) {
	readErr := errors.New("read blew up")
	wanted := map[string]struct{}{"ghp_token": {}}
	values := make(map[string]streamMatch)
	if err := findReaderMatches(context.Background(), failingReaderAt{err: readErr}, 4096, wanted, values); !errors.Is(err, readErr) {
		t.Fatalf("scan err=%v, want read error", err)
	}
}

func TestStreamRawGroupLongestCommonPrefix(t *testing.T) {
	group := &streamRawGroup{patterns: map[string]string{
		"ghp_aaaa": "ghp_aaaa", "ghp_bbbb": "ghp_bbbb",
	}}
	group.longestCommonPrefix()
	if string(group.prefix) != "ghp_" || group.single != "" {
		t.Fatalf("prefix=%q single=%q, want ghp_/empty", group.prefix, group.single)
	}
	group = &streamRawGroup{patterns: map[string]string{"ghp_aaaa": "ghp_aaaa", "gho_bbbb": "gho_bbbb"}}
	group.longestCommonPrefix()
	if string(group.prefix) != "gh" {
		t.Fatalf("prefix=%q, want gh", group.prefix)
	}
	group = &streamRawGroup{patterns: map[string]string{"ga": "ga", "gb": "gb"}}
	group.longestCommonPrefix()
	if string(group.prefix) != "g" {
		t.Fatalf("prefix=%q, want g", group.prefix)
	}
	group = &streamRawGroup{patterns: map[string]string{"solo": "solo"}}
	group.longestCommonPrefix()
	if string(group.prefix) != "solo" || group.single != "solo" {
		t.Fatalf("prefix=%q single=%q, want solo/solo", group.prefix, group.single)
	}
}

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
	eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, result, cache)
	shared["marker"] = "second"
	eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, result, cache)
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

func TestStreamFindingBatchFlushesAtLimitAndReusesSpanCache(t *testing.T) {
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{&normalizedRawDetector{}}, Options{Concurrency: 1}, sink)
	raw := []byte("batch-limit-token")
	cache := newStreamMatchCache(bytes.NewReader(raw), int64(len(raw)))
	batch := &streamFindingBatch{}
	cache.pending = batch
	chunk := &sources.Chunk{SourceType: sources.SourceFilesystem}
	emit := func(raw []byte) {
		eng.emitDetectorResult(context.Background(), chunk, decoder.Variant{}, "", 0, true, detectors.Result{
			DetectorType: detectors.AWS,
			Raw:          raw,
		}, cache)
	}

	// Pending is bounded by retained bytes, not a fixed finding count. The
	// first emit queues the raw; distinct ~1 MiB raws then grow the batch
	// until the byte cap forces a flush. The cap-crossing finding itself
	// lands in the next batch.
	emit(raw)
	var emitted int
	for i := 0; emitted == 0; i++ {
		if i > 64 {
			t.Fatal("pending never reached the byte cap")
		}
		big := bytes.Repeat([]byte{'k'}, 1<<20)
		copy(big, fmt.Sprintf("batch-limit-raw-%d", i))
		emit(big)
		emitted = len(sink.Findings())
	}
	emit([]byte("still-pending-raw"))
	cache.pending = nil
	batch.flush(context.Background(), eng, chunk, cache)
	if got, want := len(sink.Findings()), emitted+2; got != want {
		t.Fatalf("findings after final flush=%d, want %d", got, want)
	}

	// A resolved raw arriving on an empty batch emits straight through
	// without touching pending.
	batch = &streamFindingBatch{}
	cache.pending = batch
	emit(raw)
	emit(raw)
	if got, want := len(sink.Findings()), emitted+4; got != want {
		t.Fatalf("findings after resolved-raw emits=%d, want %d", got, want)
	}
	if len(batch.findings) != 0 {
		t.Fatalf("resolved raw entered pending: %d findings", len(batch.findings))
	}
	cache.pending = nil
	batch.flush(context.Background(), eng, chunk, cache)
}

// earlierOccurrenceDetector emits a fixed raw whenever its trigger keyword is
// dispatched, so the raw bytes can sit earlier in the body in non-detection
// context (no keyword nearby).
type earlierOccurrenceDetector struct{}

func (*earlierOccurrenceDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*earlierOccurrenceDetector) Keywords() []string { return []string{"emit-earlier-token"} }

func (*earlierOccurrenceDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if !bytes.Contains(data, []byte("emit-earlier-token")) {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detectors.AWS,
		Raw:          []byte("SHARED_EARLIER_TOKEN"),
	}}, nil
}

// The first-occurrence contract: a raw planted before the detection window in
// non-detection context must resolve to that earlier position, not to the
// in-window position where it was emitted.
func TestStreamFindingResolvesEarlierNonDetectionOccurrence(t *testing.T) {
	raw := []byte("SHARED_EARLIER_TOKEN")
	data := bytes.Repeat([]byte{' '}, 2*maxWindowSize)
	data[0], data[1], data[2] = '\n', '\n', '\n'
	copy(data[64:], raw)
	triggerAt := maxWindowSize + windowOverlap + 64
	copy(data[triggerAt:], "emit-earlier-token")

	findings := sinkFindings(t, lazyReaderChunk(data, "/fixture/earlier.txt"), &earlierOccurrenceDetector{})
	if len(findings) != 1 {
		t.Fatalf("findings=%d, want 1", len(findings))
	}
	span := findings[0].RawSpan
	if span == nil || span[0] != 64 || span[1] != 64+len(raw) {
		t.Fatalf("span=%v, want first occurrence at [64,%d)", span, 64+len(raw))
	}
	if line := findings[0].Chunk.SourceMetadata.Filesystem.Line; line != 4 {
		t.Fatalf("line=%d, want first-occurrence line 4", line)
	}
}

func sinkFindings(t *testing.T, chunk *sources.Chunk, d detectors.Detector) []Finding {
	t.Helper()
	sink := &engineRecordingSink{}
	eng := NewWithDetectors([]detectors.Detector{d}, Options{Concurrency: 1}, sink)
	if _, err := eng.RunWithStats(context.Background(), &stubSource{chunks: []*sources.Chunk{chunk}}); err != nil {
		t.Fatalf("run: %v", err)
	}
	return sink.Findings()
}

// rescanProbeDetector emits every probe token occurrence in its input as a
// distinct raw, letting the regression test generate >1024 unique raws.
type rescanProbeDetector struct{}

const rescanTokenPrefix = "RESCAN_TOKEN_"

func (*rescanProbeDetector) Type() detectors.DetectorType { return detectors.AWS }

func (*rescanProbeDetector) Keywords() []string { return []string{rescanTokenPrefix} }

func (*rescanProbeDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var out []detectors.Result
	for off := 0; ; {
		i := bytes.Index(data[off:], []byte(rescanTokenPrefix))
		if i < 0 {
			return out, nil
		}
		start := off + i
		end := start + len(rescanTokenPrefix) + 6
		if end > len(data) {
			return out, nil
		}
		out = append(out, detectors.Result{DetectorType: detectors.AWS, Raw: bytes.Clone(data[start:end])})
		off = end
	}
}

// Issue #437: more than 1,024 distinct raws used to force one resolve pass
// over the source head per 1,024-finding batch — O(batches × input) re-reads.
// With byte-bounded pending, the whole variant resolves in a single pass.
func TestStreamFindingRescanDoesNotScaleWithBatches(t *testing.T) {
	const (
		size   = 8 << 20
		tokens = 8*1024 + 1
	)
	data := bytes.Repeat([]byte{' '}, size)
	for i := 0; i < tokens; i++ {
		token := fmt.Sprintf("%s%06d", rescanTokenPrefix, i)
		copy(data[i*(size/tokens):], token)
	}
	reader := &countingReaderAt{reader: bytes.NewReader(data)}
	chunk := &sources.Chunk{
		SourceType: sources.SourceFilesystem,
		Open: func(context.Context) (io.ReaderAt, io.Closer, int64, error) {
			return reader, io.NopCloser(strings.NewReader("")), int64(size), nil
		},
		SourceMetadata: sources.Metadata{
			Filesystem: &sources.FilesystemMeta{Path: "/fixture/rescan.txt", Line: 1},
		},
	}
	findings := sinkFindings(t, chunk, &rescanProbeDetector{})
	if len(findings) == 0 {
		t.Fatal("no findings emitted")
	}
	// Detection and decoder walks already cost a few full-input passes; the
	// old 1,024-finding batch loop added ~half a pass per batch on top
	// (~5 extra passes here). Bound total logical reads well under that.
	if got, limit := reader.bytes.Load(), int64(8*size); got >= limit {
		t.Fatalf("logical reads=%d bytes (%.1fx input), want < %.1fx", got, float64(got)/float64(size), float64(limit)/float64(size))
	}
	t.Logf("logical reads=%d bytes (%.2fx input), calls=%d", reader.bytes.Load(), float64(reader.bytes.Load())/float64(size), reader.calls.Load())
	for i, f := range findings[:min(len(findings), 8)] {
		if f.RawSpan == nil {
			t.Fatalf("finding %d missing RawSpan", i)
		}
	}
}
