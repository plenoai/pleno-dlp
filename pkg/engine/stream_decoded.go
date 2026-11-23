package engine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"

	"github.com/plenoai/pleno-dlp/pkg/decoder"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// streamInlineRadius bounds the source bytes read around a streamed decoded
// finding to evaluate inline pragmas. Raw stream windows are bounded the same
// way (maxWindowSize), so a pragma further than this from the secret on the
// same or previous line is not seen in either streamed variant.
const streamInlineRadius = 64 << 10

// resolveDecoded maps every decoded finding in the batch back to the encoded
// bytes of the raw reader, so streamed decoded findings get the same line,
// RawSpan, and inline-pragma evaluation as buffered ones (#964, #977). It
// returns which findings were mapped; the rest keep the raw-lookup fallback.
func (b *streamFindingBatch) resolveDecoded(ctx context.Context, e *Engine, c *sources.Chunk, cache *streamMatchCache) []bool {
	mapped := make([]bool, len(b.findings))
	if b.source == "" || b.variant == nil || cache == nil || cache.reader == nil {
		return mapped
	}
	idx := make([]int, 0, len(b.findings))
	spans := make([][2]int64, 0, len(b.findings))
	for i := range b.findings {
		f := &b.findings[i]
		raw := f.Result.Raw
		if len(raw) == 0 {
			continue
		}
		if !f.decodedOK {
			// Full-chunk reader detectors have no window; locate Raw in the
			// variant the way windowMatchIndex does for buffered data.
			off, _, err := findReaderMatch(ctx, b.variant, b.variantSize, raw)
			if err != nil {
				e.recordStreamDecodedErr(ctx, c, err)
				return mapped
			}
			if off < 0 {
				continue
			}
			f.decodedAt, f.decodedOK = off, true
		}
		idx = append(idx, i)
		spans = append(spans, [2]int64{f.decodedAt, f.decodedAt + int64(len(raw))})
	}
	if len(idx) == 0 {
		return mapped
	}
	src, ok, err := decoder.StreamSourceSpans(ctx, cache.reader, cache.size, b.source, spans)
	if err != nil {
		e.recordStreamDecodedErr(ctx, c, err)
		return mapped
	}
	order := make([]int, 0, len(idx))
	for j := range idx {
		if ok[j] && src[j][1] <= cache.size {
			order = append(order, j)
		}
	}
	slices.SortFunc(order, func(a, b int) int { return compareInt64(src[a][0], src[b][0]) })
	offsets := make([]int64, len(order))
	for k, j := range order {
		offsets[k] = src[j][0]
	}
	newlines, err := countReaderNewlines(ctx, cache.reader, cache.size, offsets)
	if err != nil {
		e.recordStreamDecodedErr(ctx, c, err)
		return mapped
	}
	var region []byte
	for k, j := range order {
		f := &b.findings[idx[j]]
		s, end := src[j][0], src[j][1]
		if hasSourceLine(f.Chunk) {
			base := sourceLine(f.Chunk)
			if base <= 0 {
				base = 1
			}
			f.Chunk = chunkForFinding(f.Chunk, base+newlines[k], true)
		}
		if uint64(end) <= uint64(^uint(0)>>1) {
			f.RawSpan = &[2]int{int(s), int(end)}
		}
		inline, buf, err := readerInlineAllowed(ctx, cache.reader, cache.size, s, end, region, e.inlineTokens)
		region = buf
		if err != nil {
			e.recordStreamDecodedErr(ctx, c, err)
			return mapped
		}
		f.InlineAllowed = inline
		mapped[idx[j]] = true
	}
	return mapped
}

func (e *Engine) recordStreamDecodedErr(ctx context.Context, c *sources.Chunk, err error) {
	if ctx.Err() == nil {
		e.recordFailure(ScanFailure{Kind: FailureSource, Source: archiveFailureSource(c), Err: err})
	}
}

func compareInt64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// countReaderNewlines returns, for each ascending offset, the number of '\n'
// bytes in reader before it, in one bounded forward pass.
func countReaderNewlines(ctx context.Context, reader io.ReaderAt, size int64, offsets []int64) ([]int, error) {
	out := make([]int, len(offsets))
	if len(offsets) == 0 {
		return out, nil
	}
	buf := make([]byte, 64<<10)
	var pos int64
	count, k := 0, 0
	for k < len(offsets) {
		for k < len(offsets) && offsets[k] <= pos {
			out[k] = count
			k++
		}
		if k == len(offsets) || pos >= size {
			break
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n := min(int64(len(buf)), size-pos, offsets[len(offsets)-1]-pos)
		block := buf[:n]
		got, err := reader.ReadAt(block, pos)
		if err != nil && !(errors.Is(err, io.EOF) && got == len(block)) {
			return nil, err
		}
		if got != len(block) {
			return nil, io.ErrUnexpectedEOF
		}
		for k < len(offsets) && offsets[k] < pos+n {
			out[k] = count + bytes.Count(block[:offsets[k]-pos], []byte{'\n'})
			k++
		}
		count += bytes.Count(block, []byte{'\n'})
		pos += n
	}
	for ; k < len(offsets); k++ {
		out[k] = count
	}
	return out, nil
}

// readerInlineAllowed evaluates inlineAllowedAt on the source bytes within
// streamInlineRadius of [start, end). buf is reused across calls.
func readerInlineAllowed(ctx context.Context, reader io.ReaderAt, size, start, end int64, buf []byte, tokens [][]byte) (bool, []byte, error) {
	if end-start > streamInlineRadius {
		end = start + streamInlineRadius
	}
	lo := max(0, start-streamInlineRadius)
	hi := min(size, end+streamInlineRadius)
	if err := ctx.Err(); err != nil {
		return false, buf, err
	}
	n := int(hi - lo)
	if cap(buf) < n {
		buf = make([]byte, n)
	}
	region := buf[:n]
	got, err := reader.ReadAt(region, lo)
	if err != nil && !(errors.Is(err, io.EOF) && got == n) {
		return false, buf, err
	}
	if got != n {
		return false, buf, io.ErrUnexpectedEOF
	}
	return inlineAllowedAt(region, int(start-lo), int(end-lo), tokens...), buf, nil
}
