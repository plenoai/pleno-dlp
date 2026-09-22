package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math/rand"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"testing"
)

func TestLazyRawObservationBootstrapsBoundariesAndFindsEarlier(t *testing.T) {
	const (
		size      = 128 << 10
		windowAt  = 96 << 10
		windowLen = 32 << 10
	)
	raw := []byte("gh-earlier-token")
	for _, test := range []struct {
		name  string
		early int
	}{
		{name: "bootstrap block boundary", early: 65535},
		{name: "activation window boundary", early: windowAt - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := bytes.Repeat([]byte{' '}, size)
			copy(data[test.early:], raw)
			current := windowAt + windowLen - len(raw) // the current-window tail.
			copy(data[current:], raw)
			window := data[windowAt : windowAt+windowLen]
			reader := &countingReaderAt{reader: bytes.NewReader(data)}
			cache := newStreamMatchCache(reader, int64(len(data)))
			ctx := context.Background()
			for i := 0; i < streamRawObservationMinCandidates-1; i++ {
				candidate := []byte("gh-candidate-" + string(rune('a'+i)))
				if err := cache.observeRawCandidate(ctx, window, windowAt, candidate); err != nil {
					t.Fatalf("candidate %d: %v", i, err)
				}
			}
			if cache.observationActive || cache.firstPair != nil {
				t.Fatal("observation activated before the distinct-candidate threshold")
			}
			if err := cache.observeRawCandidate(ctx, window, windowAt, raw); err != nil {
				t.Fatalf("activate observation: %v", err)
			}
			if !cache.observationActive {
				t.Fatal("observation did not activate")
			}
			hint := streamRawHint{offset: int64(current), ok: true}
			if err := cache.resolve(ctx, [][]byte{raw}, []streamRawHint{hint}); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			match, ok := cache.lookup(raw)
			if !ok || !match.found || match.offset != int64(test.early) {
				t.Fatalf("match=%#v/%v, want earliest offset %d", match, ok, test.early)
			}
		})
	}
}

type observationErrorReader struct {
	data []byte
	err  error
}

func (r *observationErrorReader) ReadAt(p []byte, off int64) (int, error) {
	if off == 0 {
		return 0, r.err
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

func TestLazyRawObservationBootstrapErrorRollsBack(t *testing.T) {
	data := bytes.Repeat([]byte{' '}, 128<<10)
	readErr := errors.New("bootstrap failed")
	cache := newStreamMatchCache(&observationErrorReader{data: data, err: readErr}, int64(len(data)))
	window := data[96<<10:]
	for i := 0; i < streamRawObservationMinCandidates-1; i++ {
		if err := cache.observeRawCandidate(context.Background(), window, 96<<10, []byte("gh-error-"+string(rune('a'+i)))); err != nil {
			t.Fatalf("candidate %d: %v", i, err)
		}
	}
	err := cache.observeRawCandidate(context.Background(), window, 96<<10, []byte("gh-error-final"))
	if !errors.Is(err, readErr) {
		t.Fatalf("bootstrap error=%v, want %v", err, readErr)
	}
	if cache.observationActive || cache.firstPair != nil || cache.restPairFull != nil {
		t.Fatalf("failed bootstrap retained observation state: active=%v first=%v full=%v", cache.observationActive, cache.firstPair, cache.restPairFull)
	}
}

type observationCancelReader struct {
	reader io.ReaderAt
	cancel context.CancelFunc
	calls  int
}

func (r *observationCancelReader) ReadAt(p []byte, off int64) (int, error) {
	r.calls++
	n, err := r.reader.ReadAt(p, off)
	if r.calls == 1 {
		r.cancel()
	}
	return n, err
}

func TestLazyRawObservationBootstrapCancellation(t *testing.T) {
	data := bytes.Repeat([]byte{' '}, 128<<10)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &observationCancelReader{reader: bytes.NewReader(data), cancel: cancel}
	cache := newStreamMatchCache(reader, int64(len(data)))
	window := data[96<<10:]
	for i := 0; i < streamRawObservationMinCandidates-1; i++ {
		if err := cache.observeRawCandidate(ctx, window, 96<<10, []byte("gh-cancel-"+string(rune('a'+i)))); err != nil {
			t.Fatalf("candidate %d: %v", i, err)
		}
	}
	err := cache.observeRawCandidate(ctx, window, 96<<10, []byte("gh-cancel-final"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("bootstrap error=%v, want %v", err, context.Canceled)
	}
	if cache.observationActive || cache.firstPair != nil {
		t.Fatal("canceled bootstrap activated observation")
	}
}

type randomPrefixWindowDetector struct{}

func (*randomPrefixWindowDetector) Type() detectors.DetectorType { return detectors.AWS }
func (*randomPrefixWindowDetector) Keywords() []string           { return []string{"raw-test:"} }
func (*randomPrefixWindowDetector) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	var results []detectors.Result
	for {
		at := bytes.Index(data, []byte("raw-test:"))
		if at < 0 || at+9+16 > len(data) {
			return results, nil
		}
		results = append(results, detectors.Result{DetectorType: detectors.AWS, Raw: data[at+9 : at+9+16]})
		data = data[at+9+16:]
	}
}

func TestLazyObservationBoundsRawWindowDispatchReads(t *testing.T) {
	const size, count = 2 << 20, 1536
	for _, test := range []struct {
		name   string
		stride int
		budget int64
	}{
		{"rare prefixes", 512, size / 2},
		// This layout includes raws whose prefix also occurs in the repeated
		// detector marker, requiring the bounded shared-scan fallback.
		{"marker prefix collision", 1024, size},
	} {
		t.Run(test.name, func(t *testing.T) {
			data := make([]byte, size)
			rand.New(rand.NewSource(1)).Read(data)
			wanted := make(map[string]int, count)
			for i := 0; i < count; i++ {
				offset := i*test.stride + 31
				copy(data[offset-9:], "raw-test:")
				wanted[string(data[offset:offset+16])] = offset
			}
			reader := bytes.NewReader(data)
			positionReader := &countingReaderAt{reader: reader}
			cache := newStreamMatchCache(positionReader, size)
			batch := &streamFindingBatch{}
			cache.pending = batch
			sink := &engineRecordingSink{}
			eng := NewWithDetectors([]detectors.Detector{&randomPrefixWindowDetector{}}, Options{Concurrency: 1}, sink)
			chunk := lazyReaderChunk(data, "/fixture/lazy-observation.txt")
			var lower []byte
			// The production window/dispatch/batch path creates every hint itself.
			// Separate wrappers over the same bytes count attribution reads only.
			if err := eng.scanVariantWindowsReader(context.Background(), chunk, "", reader, size, "", &lower, make([]byte, maxWindowSize), cache); err != nil {
				t.Fatal(err)
			}
			cache.pending = nil
			batch.flush(context.Background(), eng, chunk, cache)
			if err := eng.takeFailures(); err != nil {
				t.Fatal(err)
			}
			if !cache.observationActive {
				t.Fatal("raw dispatch did not activate observation")
			}
			seen := make(map[string]struct{}, count)
			for _, finding := range sink.Findings() {
				raw := string(finding.Result.Raw)
				offset, ok := wanted[raw]
				if !ok || finding.RawSpan == nil || *finding.RawSpan != [2]int{offset, offset + 16} {
					t.Fatalf("unexpected raw/span: known=%v span=%v", ok, finding.RawSpan)
				}
				if line := finding.Chunk.SourceMetadata.Filesystem.Line; line != 1+bytes.Count(data[:offset], []byte{'\n'}) {
					t.Fatalf("line=%d at offset %d", line, offset)
				}
				seen[raw] = struct{}{}
			}
			if len(seen) != count {
				t.Fatalf("unique raws=%d, want %d", len(seen), count)
			}
			if got := positionReader.bytes.Load(); got > test.budget {
				t.Fatalf("position reads=%d, want <=%d across raw dispatch batches", got, test.budget)
			}
			t.Logf("position reads: bytes=%d calls=%d for %d distinct raws", positionReader.bytes.Load(), positionReader.calls.Load(), len(seen))
		})
	}
}
