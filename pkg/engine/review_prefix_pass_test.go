package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

// A saturated-prefix batch with many distinct prefixes must not scan the
// input once per prefix: all indexes a batch needs are built in one shared
// pass.
func TestDistinctSaturatedPrefixesDoNotRescanPerPrefix(t *testing.T) {
	const size = 4 << 20
	prefixes := []string{"aa", "ab", "ac", "ad", "ae", "af", "ag", "ah",
		"ai", "aj", "ak", "al", "am", "an", "ao", "ap"}
	data := bytes.Repeat([]byte{' '}, size)
	raws := make([][]byte, len(prefixes))
	hints := make([]streamRawHint, len(prefixes))
	wanted := make(map[string]struct{}, len(prefixes))
	for i, prefix := range prefixes {
		raw := []byte(fmt.Sprintf("%swanted_token_%02d", prefix, i))
		raws[i] = raw
		wanted[string(raw)] = struct{}{}
		for occurrence := 0; occurrence < 65; occurrence++ {
			offset := (occurrence*len(prefixes)+i)*256 + 32
			if occurrence == 0 {
				copy(data[offset:], raw)
				hints[i] = streamRawHint{offset: int64(offset), ok: true}
			} else {
				copy(data[offset:], prefix)
			}
		}
	}

	indexedReader := &countingReaderAt{reader: bytes.NewReader(data)}
	indexed := newStreamMatchCache(indexedReader, int64(len(data)))
	indexed.observeRawWindow("", data, 0)
	if err := indexed.resolve(context.Background(), raws, hints); err != nil {
		t.Fatalf("indexed resolve: %v", err)
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
	t.Logf("16 saturated prefixes: indexed calls=%d bytes=%d; shared calls=%d bytes=%d; byte ratio=%.1fx",
		indexedCalls, indexedBytes, sharedCalls, sharedBytes, float64(indexedBytes)/float64(sharedBytes))
	if indexedBytes > 2*size {
		t.Fatalf("one batch must not scan the full input once per prefix: indexed=%d, want <=%d", indexedBytes, 2*size)
	}
}

func TestSaturatedPrefixFastScanPreservesLineAttribution(t *testing.T) {
	for _, raw := range [][]byte{[]byte("gh-target"), []byte("a")} {
		t.Run(string(raw), func(t *testing.T) {
			data := bytes.Repeat([]byte("gh\na\n"), hintVerifyCandidateCap+8)
			offset := int64(len(data) - len(raw))
			copy(data[offset:], raw)
			cache := newStreamMatchCache(bytes.NewReader(data), int64(len(data)))
			cache.observeRawWindow("", data, 0)
			if err := cache.resolve(context.Background(), [][]byte{raw}, []streamRawHint{{offset: offset, ok: true}}); err != nil {
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

// A candidate read that comes back short (fewer bytes than the raw needs)
// must propagate io.ErrUnexpectedEOF rather than silently ruling the
// candidate out.
func TestHintPropagatesShortCandidateRead(t *testing.T) {
	raw := []byte("abcde")
	reader := &shortReaderAt{data: []byte("small-reader-body")}
	cache := newStreamMatchCache(reader, 100)
	cache.observeRawWindow("", []byte("ab"), 50) // 'ab' candidate at offset 51
	err := cache.resolve(context.Background(), [][]byte{raw},
		[]streamRawHint{{offset: 99, ok: true}})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("resolve err=%v, want io.ErrUnexpectedEOF", err)
	}
}
