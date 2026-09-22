package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
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
