package git

import (
	"bytes"
	"fmt"
)

// nativeLineFeed hands rendered patch text straight to a nativeLogParser
// on the rendering goroutine (#1041). The stream renderer used to write
// every commit into an io.Pipe that a second goroutine re-buffered and
// re-split; feeding the lines in place drops the pipe copy, the
// goroutine handoff, and both 256 KiB stream buffers per worker. Lines are
// passed to consumeLine exactly as parse would pass them; only a line that
// spans Write calls (git fallback output) is copied into carry.
type nativeLineFeed struct {
	p     *nativeLogParser
	carry []byte
	err   error
}

func (f *nativeLineFeed) Write(b []byte) (int, error) {
	if f.err != nil {
		return 0, f.err
	}
	n := len(b)
	if len(f.carry) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			f.carry = append(f.carry, b...)
			if err := f.checkCarry(); err != nil {
				return 0, err
			}
			return n, nil
		}
		f.carry = append(f.carry, b[:i+1]...)
		if err := f.line(f.carry); err != nil {
			return 0, err
		}
		f.carry = f.carry[:0]
		b = b[i+1:]
	}
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			f.carry = append(f.carry[:0], b...)
			if err := f.checkCarry(); err != nil {
				return 0, err
			}
			break
		}
		if err := f.line(b[:i+1]); err != nil {
			return 0, err
		}
		b = b[i+1:]
	}
	return n, nil
}

// writeLines is Write for p whose lines from body on end at the offsets in
// ends (the last one len(p)), as the in-process renderer records them; the
// header before body is split as Write would split it (#1046).
func (f *nativeLineFeed) writeLines(p []byte, body int, ends []int) error {
	if f.err != nil || len(f.carry) > 0 || len(ends) == 0 || ends[len(ends)-1] != len(p) {
		_, err := f.Write(p)
		return err
	}
	if _, err := f.Write(p[:body]); err != nil {
		return err
	}
	start := body
	for _, end := range ends {
		if err := f.line(p[start:end]); err != nil {
			return err
		}
		start = end
	}
	return nil
}

// Flush consumes a final unterminated line.
func (f *nativeLineFeed) Flush() error {
	if f.err != nil {
		return f.err
	}
	if len(f.carry) == 0 {
		return nil
	}
	err := f.line(f.carry)
	f.carry = f.carry[:0]
	return err
}

// checkCarry applies parse's line limit to a partial line: only hunk lines
// (which parse streams in fragments) may exceed it.
func (f *nativeLineFeed) checkCarry() error {
	if len(f.carry) > int(maxBlobSize)+1 && !f.p.fragmentedHunkLine(f.carry) {
		f.err = fmt.Errorf("native output line exceeds %d-byte limit", maxBlobSize)
	}
	return f.err
}

func (f *nativeLineFeed) line(l []byte) error {
	if len(l) > int(maxBlobSize)+1 && !f.p.fragmentedHunkLine(l) {
		f.err = fmt.Errorf("native output line exceeds %d-byte limit", maxBlobSize)
		return f.err
	}
	if err := f.p.consumeLine(l); err != nil {
		f.err = err
		return err
	}
	return nil
}

// nativeSectionSkipper forwards git's rendering of one commit minus its
// header and first skip "diff --git" sections, which the in-process
// renderer already sent byte-identically before a blob forced a fallback.
type nativeSectionSkipper struct {
	out     nativeSynthSink
	skip    int
	seen    int // "diff --git" headers seen
	passing bool
	atBOL   bool // the next byte starts a line
	started bool
	line    []byte // partial line prefix, kept only until it is classified
}

var nativeDiffHeader = []byte("diff --git ")

func (s *nativeSectionSkipper) Write(b []byte) (int, error) {
	n := len(b)
	if !s.started {
		s.started, s.atBOL = true, true
	}
	for len(b) > 0 {
		if s.passing {
			_, err := s.out.Write(b)
			return n, err
		}
		if s.atBOL || len(s.line) > 0 {
			// Classify the line once enough of it is known.
			need := len(nativeDiffHeader) - len(s.line)
			take := min(need, len(b))
			if i := bytes.IndexByte(b[:take], '\n'); i >= 0 {
				take = i + 1
			}
			s.line = append(s.line, b[:take]...)
			b = b[take:]
			s.atBOL = false
			isHeader := bytes.Equal(s.line, nativeDiffHeader)
			ended := s.line[len(s.line)-1] == '\n'
			if !isHeader && !ended && len(s.line) < len(nativeDiffHeader) {
				continue
			}
			if isHeader {
				s.seen++
				if s.seen > s.skip {
					s.passing = true
					head := s.line
					s.line = s.line[:0]
					if _, err := s.out.Write(head); err != nil {
						return n, err
					}
					continue
				}
			}
			s.line = s.line[:0]
			if ended {
				s.atBOL = true
				continue
			}
		}
		// Drop the rest of a skipped line.
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			return n, nil
		}
		b = b[i+1:]
		s.atBOL = true
	}
	return n, nil
}

func (s *nativeSectionSkipper) flush() error { return nil }
