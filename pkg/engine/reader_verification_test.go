package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"

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
