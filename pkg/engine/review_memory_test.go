package engine

import (
	"bytes"
	"context"
	"runtime"
	"sync/atomic"
	"testing"
)

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
	cache.observeRawWindow("", data, 0)
	if err := cache.resolve(context.Background(), [][]byte{raw}, []streamRawHint{{offset: offset, ok: true}}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	if !ok || !match.found || match.offset != offset {
		t.Fatalf("raw match=%#v/%v, want offset=%d", match, ok, offset)
	}
	t.Logf("input=%d raw_len=%d raw_offset=%d prefix_cap=%d peak_heap_delta=%d bytes reader_calls=%d reader_bytes=%d",
		len(data), len(raw), offset, streamPrefixIndexCap,
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
	cache.observeRawWindow("", data, 0)
	if err := cache.resolve(context.Background(), [][]byte{raw}, []streamRawHint{{offset: offset, ok: true}}); err != nil {
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
