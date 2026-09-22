package engine

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
)

type reviewIndexFailReader struct {
	data   []byte
	failAt int64
	err    error
}

func (r *reviewIndexFailReader) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.failAt {
		return 0, r.err
	}
	return bytes.NewReader(r.data).ReadAt(p, off)
}

type reviewIndexCancelReader struct {
	data   []byte
	cancel context.CancelFunc
	calls  atomic.Int64
}

func (r *reviewIndexCancelReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := bytes.NewReader(r.data).ReadAt(p, off)
	if r.calls.Add(1) == 1 {
		r.cancel()
	}
	return n, err
}

func reviewIndexPairKey(a, b byte) uint32 {
	return uint32(a)<<8 | uint32(b)
}

func TestPrefixIndexBuildErrorRollsBackSampleCounter(t *testing.T) {
	data := bytes.Repeat([]byte("gh"), 1<<16)
	reader := &reviewIndexFailReader{data: data, failAt: 65536, err: errors.New("index read failed")}
	cache := newStreamMatchCache(reader, int64(len(data)))
	_, err := cache.prefixIndexes(context.Background(), []uint32{reviewIndexPairKey('g', 'h')})
	if !errors.Is(err, reader.err) {
		t.Fatalf("prefix index error=%v, want %v", err, reader.err)
	}
	if cache.indexedPositions != 0 || cache.indexSampleBytes != 0 {
		t.Fatalf("failed build retained positions=%d samples=%d, want zero", cache.indexedPositions, cache.indexSampleBytes)
	}
}

func TestPrefixIndexBuildCancellationRollsBackSampleCounter(t *testing.T) {
	data := bytes.Repeat([]byte("gh"), 1<<16)
	ctx, cancel := context.WithCancel(context.Background())
	reader := &reviewIndexCancelReader{data: data, cancel: cancel}
	cache := newStreamMatchCache(reader, int64(len(data)))
	_, err := cache.prefixIndexes(ctx, []uint32{reviewIndexPairKey('g', 'h')})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("prefix index error=%v, want %v", err, context.Canceled)
	}
	if cache.indexedPositions != 0 || cache.indexSampleBytes != 0 {
		t.Fatalf("canceled build retained positions=%d samples=%d, want zero", cache.indexedPositions, cache.indexSampleBytes)
	}
}

type reviewRealisticPeakReader struct {
	reader *bytes.Reader
	peak   atomic.Uint64
	calls  atomic.Int64
	bytes  atomic.Int64
}

func (r *reviewRealisticPeakReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.reader.ReadAt(p, off)
	r.calls.Add(1)
	r.bytes.Add(int64(len(p)))
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	for {
		old := r.peak.Load()
		if stats.HeapAlloc <= old || r.peak.CompareAndSwap(old, stats.HeapAlloc) {
			break
		}
	}
	return n, err
}

// TestReviewRealisticPrefixIndexCapMemory exercises the real resolver with a
// 40-byte GitHub raw near the tail of a dense shared-prefix body. It records
// Go heap allocation after each ReaderAt block under the default GC settings;
// this is a diagnostic of transient heap pressure, not CLI RSS evidence.
func TestReviewRealisticPrefixIndexCapMemory(t *testing.T) {
	const rawText = "ghp_123456789012345678901234567890123456"
	raw := []byte(rawText)
	if len(raw) != 40 {
		t.Fatalf("raw length=%d, want 40", len(raw))
	}
	const pairs = (4 << 20) + 32
	data := bytes.Repeat([]byte("gh"), pairs)
	offset := int64(len(data) - len(raw))
	copy(data[offset:], raw)
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	reader := &reviewRealisticPeakReader{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(reader, int64(len(data)))
	if err := cache.resolve(context.Background(), [][]byte{raw}, nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	if !ok || !match.found || match.offset != offset {
		t.Fatalf("raw match=%#v/%v, want offset=%d", match, ok, offset)
	}
	t.Logf("input=%d raw_len=%d raw_offset=%d prefix_cap=%d peak_heap_delta=%d bytes reader_calls=%d reader_bytes=%d",
		len(data), len(raw), offset, streamPrefixIndexTotalCap,
		reader.peak.Load()-before.HeapAlloc, reader.calls.Load(), reader.bytes.Load())
}

// TestPrefixIndexStorageBudgetFallback is the deterministic storage-budget
// regression: a prefix denser than the retained-position budget must drop
// its index (marked OOM, nothing retained) and still resolve the raw via
// the bounded shared scan.
func TestPrefixIndexStorageBudgetFallback(t *testing.T) {
	// 'gh' occurrences exceed the retained-position budget by a clear
	// margin; every other byte in the body is the same prefix.
	pairs := streamPrefixIndexTotalCap + 256
	data := bytes.Repeat([]byte("gh"), pairs)
	raw := []byte("ghp_budget_probe_token_0000000000000001")
	offset := int64(len(data) - len(raw))
	copy(data[offset:], raw)
	reader := &countingReaderAt{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(reader, int64(len(data)))
	key := reviewIndexPairKey('g', 'h')
	if _, err := cache.prefixIndexes(context.Background(), []uint32{key}); err != nil {
		t.Fatalf("prefix index build: %v", err)
	}
	if err := cache.resolve(context.Background(), [][]byte{raw}, nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	if !ok || !match.found || match.offset != offset {
		t.Fatalf("raw match=%#v/%v, want offset=%d via shared fallback", match, ok, offset)
	}
	pairKey := uint32(uint16('g')<<8 | uint16('h'))
	if !cache.indexOOM[pairKey] {
		t.Fatal("over-budget prefix must be marked OOM")
	}
	if cache.indexFor(pairKey) != nil {
		t.Fatal("over-budget prefix index must not be retained")
	}
	if cache.indexedPositions > streamPrefixIndexTotalCap {
		t.Fatalf("retained positions=%d exceed budget %d", cache.indexedPositions, streamPrefixIndexTotalCap)
	}
}
