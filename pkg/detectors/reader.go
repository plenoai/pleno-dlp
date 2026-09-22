package detectors

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
)

// ForEachReaderPrefixedSubmatch seeks a literal marker before each regexp
// pass. Marker-based block detectors use this to keep large marker-free
// inputs on the cheap bytes.Index path; regexp still decides the complete
// match and remains the grammar authority. captures selects the submatch
// indexes to copy (0 is the complete match).
func ForEachReaderPrefixedSubmatch(ctx context.Context, input io.ReaderAt, size int64, re *regexp.Regexp, prefix []byte, captures []int, visit func([][]byte) error) error {
	return forEachReaderSubmatch(ctx, input, size, re, prefix, captures, visit)
}

// ForEachReaderLineSubmatch applies re only to lines that contain at least
// minOccurrences non-overlapping occurrences of needle and, when
// maxOccurrences is positive, no more than that many. The line scan is a
// bounded-memory byte pass; regexp remains responsible for deciding whether
// a candidate line is valid. A zero maxOccurrences keeps the upper bound open.
// The helper is useful for full-chunk detectors whose grammar has a cheap
// required separator (for example, exactly four colons in a pgpass row or
// "://" in a stored Git URL).
func ForEachReaderLineSubmatch(ctx context.Context, input io.ReaderAt, size int64, re *regexp.Regexp, needle []byte, minOccurrences, maxOccurrences int, captures []int, visit func([][]byte) error) error {
	var reFactory func() *regexp.Regexp
	if re != nil {
		reFactory = func() *regexp.Regexp { return re }
	}
	return forEachReaderLineSubmatch(ctx, input, size, reFactory, needle, minOccurrences, maxOccurrences, captures, visit)
}

// ForEachReaderLineSubmatchFunc is the lazy-regexp form of
// ForEachReaderLineSubmatch. reFactory is called at most once, and only after
// the first line passes the cheap occurrence gate. A nil factory or a nil
// regexp returned by the factory is rejected with the same error used by the
// eager helper.
func ForEachReaderLineSubmatchFunc(ctx context.Context, input io.ReaderAt, size int64, reFactory func() *regexp.Regexp, needle []byte, minOccurrences, maxOccurrences int, captures []int, visit func([][]byte) error) error {
	return forEachReaderLineSubmatch(ctx, input, size, reFactory, needle, minOccurrences, maxOccurrences, captures, visit)
}

func forEachReaderLineSubmatch(ctx context.Context, input io.ReaderAt, size int64, reFactory func() *regexp.Regexp, needle []byte, minOccurrences, maxOccurrences int, captures []int, visit func([][]byte) error) error {
	if len(needle) == 0 || minOccurrences < 1 || maxOccurrences < 0 || (maxOccurrences > 0 && maxOccurrences < minOccurrences) {
		return fmt.Errorf("detectors: invalid line match requirement")
	}
	if bytes.IndexByte(needle, '\n') >= 0 {
		return fmt.Errorf("detectors: line match requirement contains newline")
	}
	if input == nil || reFactory == nil || visit == nil || size < 0 {
		return fmt.Errorf("detectors: invalid reader match arguments")
	}
	var resolvedRe *regexp.Regexp
	resolveRegexp := func() (*regexp.Regexp, error) {
		if resolvedRe == nil {
			resolvedRe = reFactory()
		}
		if resolvedRe == nil {
			return nil, fmt.Errorf("detectors: invalid reader match arguments")
		}
		return resolvedRe, nil
	}
	wrapped := &contextReaderAt{ctx: ctx, input: input}
	reader := bufio.NewReaderSize(io.NewSectionReader(wrapped, 0, size), 32<<10)
	const readSize = 32 << 10
	carry := make([]byte, 0, len(needle)-1)
	workspace := make([]byte, 0, readSize+len(needle)-1)
	lineStart := int64(0)
	occurrences := 0
	consumed := int64(0)
	process := func(fragment []byte, hasNewline bool) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if hasNewline {
			fragment = fragment[:len(fragment)-1]
		}
		workspace = workspace[:0]
		workspace = append(workspace, carry...)
		workspace = append(workspace, fragment...)
		occurrences += bytes.Count(workspace, needle) - bytes.Count(carry, needle)
		if len(needle) > 1 {
			if len(workspace) >= len(needle)-1 {
				carry = carry[:len(needle)-1]
				copy(carry, workspace[len(workspace)-len(carry):])
			} else {
				carry = append(carry[:0], workspace...)
			}
		} else {
			carry = carry[:0]
		}
		consumed += int64(len(fragment))
		if !hasNewline {
			return nil
		}
		if occurrences >= minOccurrences && (maxOccurrences == 0 || occurrences <= maxOccurrences) {
			re, err := resolveRegexp()
			if err != nil {
				return err
			}
			if _, _, err := visitReaderSubmatch(ctx, wrapped, lineStart, consumed-lineStart, re, captures, visit); err != nil {
				return err
			}
		}
		consumed++
		lineStart = consumed
		occurrences = 0
		carry = carry[:0]
		return nil
	}
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) > 0 {
			hasNewline := fragment[len(fragment)-1] == '\n'
			if processErr := process(fragment, hasNewline); processErr != nil {
				return processErr
			}
		}
		if err == nil {
			continue
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF {
			break
		}
		return err
	}
	if lineStart < size && occurrences >= minOccurrences && (maxOccurrences == 0 || occurrences <= maxOccurrences) {
		re, err := resolveRegexp()
		if err != nil {
			return err
		}
		if _, _, err := visitReaderSubmatch(ctx, wrapped, lineStart, size-lineStart, re, captures, visit); err != nil {
			return err
		}
	}
	return finishReaderMatch(ctx, wrapped, size)
}

func forEachReaderSubmatch(ctx context.Context, input io.ReaderAt, size int64, re *regexp.Regexp, prefix []byte, captures []int, visit func([][]byte) error) error {
	if input == nil || re == nil || visit == nil || size < 0 {
		return fmt.Errorf("detectors: invalid reader match arguments")
	}
	wrapped := &contextReaderAt{ctx: ctx, input: input}
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		if len(prefix) > 0 {
			candidate, err := findReaderBytes(ctx, wrapped, size, prefix, offset)
			if err != nil {
				return err
			}
			if candidate < 0 {
				return finishReaderMatch(ctx, wrapped, size)
			}
			offset = candidate
		}
		next, found, err := visitReaderSubmatch(ctx, wrapped, offset, size-offset, re, captures, visit)
		if err != nil {
			return err
		}
		if !found {
			return finishReaderMatch(ctx, wrapped, size)
		}
		if next <= offset {
			next = offset + 1
		}
		offset = next
	}
	return finishReaderMatch(ctx, wrapped, size)
}

func visitReaderSubmatch(ctx context.Context, input *contextReaderAt, offset, length int64, re *regexp.Regexp, captures []int, visit func([][]byte) error) (int64, bool, error) {
	section := io.NewSectionReader(input, offset, length)
	indices := re.FindReaderSubmatchIndex(bufio.NewReaderSize(section, 32<<10))
	if indices == nil {
		if err := input.latchedErr(); err != nil {
			return 0, false, err
		}
		return 0, false, nil
	}
	if len(indices) < 2 || indices[0] < 0 || indices[1] < indices[0] {
		return 0, false, fmt.Errorf("detectors: invalid regexp match offsets")
	}
	groups := make([][]byte, len(captures))
	for i, capture := range captures {
		if capture < 0 || 2*capture+1 >= len(indices) {
			return 0, false, fmt.Errorf("detectors: invalid capture index %d", capture)
		}
		start, end := indices[2*capture], indices[2*capture+1]
		if start < 0 || end < start {
			continue
		}
		absoluteStart := offset + int64(start)
		absoluteEnd := offset + int64(end)
		if absoluteEnd > offset+length {
			return 0, false, fmt.Errorf("detectors: regexp match exceeds reader size")
		}
		var err error
		groups[i], err = readReaderRange(input, absoluteStart, absoluteEnd-absoluteStart)
		if err != nil {
			return 0, false, err
		}
	}
	if err := visit(groups); err != nil {
		return 0, false, err
	}
	return offset + int64(indices[1]), true, nil
}

func finishReaderMatch(ctx context.Context, input *contextReaderAt, size int64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := input.latchedErr(); err != nil {
		return err
	}
	if size > 0 {
		var one [1]byte
		n, err := input.ReadAt(one[:], size-1)
		if err != nil && !(err == io.EOF && n == len(one)) {
			return err
		}
		if n != len(one) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func findReaderBytes(ctx context.Context, input *contextReaderAt, size int64, needle []byte, offset int64) (int64, error) {
	if len(needle) == 0 {
		return offset, nil
	}
	const readSize = 32 << 10
	overlap := len(needle) - 1
	buf := make([]byte, readSize+overlap)
	carry := 0
	for offset < size {
		if err := ctx.Err(); err != nil {
			return -1, err
		}
		want := size - offset
		if want > readSize {
			want = readSize
		}
		n, err := input.ReadAt(buf[carry:carry+int(want)], offset)
		if n > 0 {
			data := buf[:carry+n]
			if index := bytes.Index(data, needle); index >= 0 {
				return offset - int64(carry) + int64(index), nil
			}
			if len(data) > overlap {
				copy(buf[:overlap], data[len(data)-overlap:])
				carry = overlap
			} else {
				copy(buf[:len(data)], data)
				carry = len(data)
			}
			offset += int64(n)
		}
		if err != nil {
			if err == io.EOF && n == int(want) {
				continue
			}
			if n < int(want) {
				return -1, io.ErrUnexpectedEOF
			}
			return -1, err
		}
		if n != int(want) {
			return -1, io.ErrUnexpectedEOF
		}
	}
	return -1, nil
}

func readReaderRange(input io.ReaderAt, offset, size int64) ([]byte, error) {
	if size == 0 {
		return []byte{}, nil
	}
	data := make([]byte, size)
	n, err := input.ReadAt(data, offset)
	if err != nil && !(err == io.EOF && int64(n) == size) {
		return nil, err
	}
	if int64(n) != size {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

type contextReaderAt struct {
	ctx   context.Context
	input io.ReaderAt
	err   error
}

func (r *contextReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.input.ReadAt(p, offset)
	if n < len(p) {
		if err != nil && err != io.EOF {
			r.err = err
		} else {
			r.err = io.ErrUnexpectedEOF
		}
		return n, r.err
	}
	if err == io.EOF {
		return n, nil
	}
	if err != nil {
		r.err = err
	}
	return n, err
}

func (r *contextReaderAt) latchedErr() error {
	return r.err
}
