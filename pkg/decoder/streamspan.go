package decoder

import (
	"bufio"
	"context"
	"errors"
	"io"
	"slices"
)

// segment64 is segment for replayable stream inputs.
type segment64 struct{ dec, decEnd, src, srcEnd int64 }

// StreamSourceSpans is SourceSpan for the variants WalkVariants produces. Each
// span is a decoded byte range [start, end) of the variant that source names
// (as passed to the WalkVariants visit callback); the result holds the
// encoding byte range of input for each span, with ok[i] false when span i
// cannot be mapped.
//
// The decoder is replayed over input once for all spans, emitting only the
// segment boundaries, so memory stays bounded by the number of spans rather
// than the input or variant size (#977).
func StreamSourceSpans(ctx context.Context, input io.ReaderAt, size int64, source string, spans [][2]int64) (out [][2]int64, ok []bool, err error) {
	out = make([][2]int64, len(spans))
	ok = make([]bool, len(spans))
	if input == nil || size < 0 {
		return out, ok, errors.New("decoder: invalid stream input")
	}
	m := newSpanMapper(spans)
	if m.pending() == 0 {
		return out, ok, nil
	}
	input = contextReaderAt{ctx, input}
	switch source {
	case "base64", "hex":
		var scan [64 * 1024]byte
		err = decodeStreamRuns(ctx, input, size, source == "base64", nil, scan[:], m.feed)
		if errors.Is(err, errStopWalk) {
			err = nil
		}
	case "percent", "unicode-escape", "utf16le", "utf16be":
		err = transformStream(input, size, source, discardWriter(), m.feed)
	default:
		return out, ok, nil
	}
	if err != nil {
		return out, ok, err
	}
	for i := range m.q {
		q := &m.q[i]
		if q.started && q.srcEnd > q.srcStart {
			out[q.idx] = [2]int64{q.srcStart, q.srcEnd}
			ok[q.idx] = true
		}
	}
	return out, ok, nil
}

type spanQuery struct {
	start, end       int64
	idx              int
	srcStart, srcEnd int64
	started, done    bool
}

// spanMapper resolves many decoded spans in one forward segment walk with the
// same interpolation SourceSpan uses.
type spanMapper struct {
	q      []spanQuery
	next   int
	active []int
	open   int
}

func newSpanMapper(spans [][2]int64) *spanMapper {
	m := &spanMapper{}
	for i, s := range spans {
		if s[0] >= 0 && s[1] > s[0] {
			m.q = append(m.q, spanQuery{start: s[0], end: s[1], idx: i})
		}
	}
	slices.SortFunc(m.q, func(a, b spanQuery) int {
		switch {
		case a.start < b.start:
			return -1
		case a.start > b.start:
			return 1
		}
		return 0
	})
	m.open = len(m.q)
	return m
}

func (m *spanMapper) pending() int { return m.open }

func (m *spanMapper) feed(s segment64) bool {
	if s.decEnd <= s.dec {
		return true
	}
	decLen, srcLen := s.decEnd-s.dec, s.srcEnd-s.src
	for m.next < len(m.q) && m.q[m.next].start < s.decEnd {
		q := &m.q[m.next]
		q.srcStart = s.src + max(q.start-s.dec, 0)*srcLen/decLen
		q.started = true
		m.active = append(m.active, m.next)
		m.next++
	}
	kept := m.active[:0]
	for _, i := range m.active {
		q := &m.q[i]
		if s.dec < q.end {
			off := min(q.end, s.decEnd) - s.dec
			q.srcEnd = s.src + (off*srcLen+decLen-1)/decLen
			if q.end <= s.decEnd {
				q.done = true
				m.open--
				continue
			}
		}
		kept = append(kept, i)
	}
	m.active = kept
	return m.open > 0
}

func discardWriter() *bufio.Writer { return bufio.NewWriterSize(io.Discard, 4096) }
