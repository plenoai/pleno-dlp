package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

// Dense groups with distinct prefixes must build their indexes in one shared
// reader pass rather than one input scan per prefix.
func TestDenseDistinctPrefixesUseOneSharedIndexPass(t *testing.T) {
	const size = 4 << 20
	prefixes := []string{"aa", "ab", "ac", "ad", "ae", "af", "ag", "ah",
		"ai", "aj", "ak", "al", "am", "an", "ao", "ap"}
	data := bytes.Repeat([]byte{' '}, size)
	raws := make([][]byte, 0, len(prefixes)*streamIndexGroupMinRaws)
	wanted := make(map[string]struct{}, len(prefixes))
	for i, prefix := range prefixes {
		for occurrence := 0; occurrence < 65; occurrence++ {
			offset := (occurrence*len(prefixes)+i)*256 + 32
			if occurrence < streamIndexGroupMinRaws {
				raw := []byte(fmt.Sprintf("%swanted_token_%02d_%02d", prefix, i, occurrence))
				raws = append(raws, raw)
				wanted[string(raw)] = struct{}{}
				copy(data[offset:], raw)
			} else {
				copy(data[offset:], prefix)
			}
		}
	}

	indexedReader := &countingReaderAt{reader: bytes.NewReader(data)}
	indexed := newStreamMatchCache(indexedReader, int64(len(data)))
	if err := indexed.resolve(context.Background(), raws, nil); err != nil {
		t.Fatalf("indexed resolve: %v", err)
	}
	for _, prefix := range prefixes {
		key, _ := prefixKey([]byte(prefix))
		if indexed.indexFor(uint32(key)) == nil {
			t.Fatalf("prefix %q has no reusable index", prefix)
		}
	}

	sharedReader := &countingReaderAt{reader: bytes.NewReader(data)}
	shared := make(map[string]streamMatch, len(wanted))
	if err := findReaderMatches(context.Background(), sharedReader, int64(len(data)), wanted, shared); err != nil {
		t.Fatalf("shared resolve: %v", err)
	}
	for _, raw := range raws {
		indexedMatch, indexedOK := indexed.lookup(raw)
		sharedMatch, sharedOK := shared[string(raw)]
		if !indexedOK || !sharedOK || indexedMatch != sharedMatch {
			t.Fatalf("raw %q: indexed=%#v/%v shared=%#v/%v", raw, indexedMatch, indexedOK, sharedMatch, sharedOK)
		}
	}

	indexedBytes := indexedReader.bytes.Load()
	sharedBytes := sharedReader.bytes.Load()
	indexedCalls := indexedReader.calls.Load()
	sharedCalls := sharedReader.calls.Load()
	t.Logf("16 prefixes: indexed calls=%d bytes=%d; shared calls=%d bytes=%d; byte ratio=%.1fx",
		indexedCalls, indexedBytes, sharedCalls, sharedBytes, float64(indexedBytes)/float64(sharedBytes))
	if indexedBytes > 2*size {
		t.Fatalf("one batch must not scan the full input once per prefix: indexed=%d, want <=%d", indexedBytes, 2*size)
	}
}

func TestSharedAndIndexedScansPreserveLineAttribution(t *testing.T) {
	for _, raw := range [][]byte{[]byte("gh-target"), []byte("a")} {
		for _, indexed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/indexed=%v", raw, indexed), func(t *testing.T) {
				data := bytes.Repeat([]byte("gh\na\n"), streamIndexGroupMinRaws+8)
				offset := int64(len(data) - len(raw))
				copy(data[offset:], raw)
				cache := newStreamMatchCache(bytes.NewReader(data), int64(len(data)))
				if indexed {
					key, single := prefixKey(raw)
					group := uint32(key)
					if single {
						group |= indexGroupSingleBit
					}
					if _, err := cache.prefixIndexes(context.Background(), []uint32{group}); err != nil {
						t.Fatal(err)
					}
				}
				if err := cache.resolve(context.Background(), [][]byte{raw}, nil); err != nil {
					t.Fatalf("resolve: %v", err)
				}
				match, ok := cache.lookup(raw)
				wantOffset := offset
				if len(raw) == 1 {
					wantOffset = int64(bytes.Index(data, raw))
				}
				wantLines := bytes.Count(data[:wantOffset], []byte{'\n'})
				if !ok || !match.found || match.offset != wantOffset || match.newlineCount != wantLines {
					t.Fatalf("match=%#v/%v, want offset=%d lines=%d", match, ok, wantOffset, wantLines)
				}
			})
		}
	}
}

func TestSmallPrefixUsesSharedScan(t *testing.T) {
	data := bytes.Repeat([]byte("gh"), 10000)
	raw := []byte("gh-small-batch-token")
	copy(data[len(data)-len(raw):], raw)
	reader := &countingReaderAt{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(reader, int64(len(data)))
	raws := make([][]byte, streamFindingBatchLimit)
	for i := range raws {
		raws[i] = raw
	}
	if err := cache.resolve(context.Background(), raws, nil); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	match, ok := cache.lookup(raw)
	if !ok || !match.found || match.offset != int64(len(data)-len(raw)) {
		t.Fatalf("match=%#v/%v, want final raw", match, ok)
	}
	key := uint32(uint16('g')<<8 | uint16('h'))
	if cache.indexFor(key) != nil || cache.indexOOM[key] {
		t.Fatalf("small group retained index=%v oom=%v", cache.indexFor(key), cache.indexOOM[key])
	}
}

func TestPrefixIndexThresholdAccumulatesAcrossBatches(t *testing.T) {
	const (
		size  = 1 << 20
		count = 96
		batch = 32
	)
	data := bytes.Repeat([]byte{' '}, size)
	raws := make([][]byte, count)
	for i := range raws {
		raws[i] = []byte(fmt.Sprintf("gh-cumulative-token-%03d", i))
		copy(data[i*(size/count):], raws[i])
	}
	reader := &countingReaderAt{reader: bytes.NewReader(data)}
	cache := newStreamMatchCache(reader, int64(len(data)))

	if err := cache.resolve(context.Background(), raws[:batch], nil); err != nil {
		t.Fatalf("first batch: %v", err)
	}
	firstBytes := reader.bytes.Load()
	prefix, _ := prefixKey(raws[0])
	groupKey := uint32(prefix)
	if cache.indexFor(groupKey) != nil {
		t.Fatal("small first batch retained an index")
	}
	if err := cache.resolve(context.Background(), raws[batch:2*batch], nil); err != nil {
		t.Fatalf("second batch: %v", err)
	}
	secondBytes := reader.bytes.Load()
	if secondBytes <= firstBytes {
		t.Fatalf("second batch did not build the cumulative index: first=%d second=%d", firstBytes, secondBytes)
	}
	if cache.indexFor(groupKey) == nil {
		t.Fatal("cumulative threshold did not retain the prefix index")
	}
	if err := cache.resolve(context.Background(), raws[2*batch:], nil); err != nil {
		t.Fatalf("third batch: %v", err)
	}
	if got := reader.bytes.Load(); got-secondBytes > int64(batch*len(raws[0])) {
		t.Fatalf("reused prefix index reread full source: before=%d after=%d", secondBytes, got)
	}
	for i, raw := range raws {
		match, ok := cache.lookup(raw)
		want := int64(i * (size / count))
		if !ok || !match.found || match.offset != want {
			t.Fatalf("raw %d = %#v/%v, want offset %d", i, match, ok, want)
		}
	}
}

// shortReaderAt reports data up to its real length only: a request that
// extends past it returns a short count with io.EOF, like a reader lying
// about its size.
type shortReaderAt struct {
	data []byte
}

func (r *shortReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// A source read that comes back short must propagate io.ErrUnexpectedEOF
// rather than silently ruling the raw out.
func TestSharedScanPropagatesShortRead(t *testing.T) {
	raw := []byte("abcde")
	reader := &shortReaderAt{data: []byte("small-reader-body")}
	cache := newStreamMatchCache(reader, 100)
	err := cache.resolve(context.Background(), [][]byte{raw}, nil)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("resolve err=%v, want io.ErrUnexpectedEOF", err)
	}
}

func TestHintPropagatesShortCandidateRead(t *testing.T) {
	raw := []byte("abcde")
	cache := newStreamMatchCache(&shortReaderAt{data: []byte("small-reader-body")}, 100)
	cache.observeRawWindow("", []byte("ab"), 50)
	err := cache.resolve(context.Background(), [][]byte{raw}, []streamRawHint{{offset: 99, ok: true}})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("resolve err=%v, want io.ErrUnexpectedEOF", err)
	}
}
