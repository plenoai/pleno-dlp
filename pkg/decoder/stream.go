package decoder

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"unicode/utf16"
	"unicode/utf8"
)

// WalkVariants is Variants for replayable inputs. Each reader is borrowed until
// visit returns. Decoded data is spooled to a private temporary file so neither
// a long encoded run nor a decoded variant must fit in memory.
func WalkVariants(ctx context.Context, input io.ReaderAt, size int64, visit func(string, io.ReaderAt, int64) error) error {
	if input == nil || visit == nil || size < 0 {
		return errors.New("decoder: invalid stream input")
	}
	input = contextReaderAt{ctx, input}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := visit("", input, size); err != nil {
		return err
	}
	for _, source := range []string{"base64", "percent", "hex", "utf16", "unicode-escape"} {
		if err := walkDecoded(ctx, input, size, source, visit); err != nil {
			return err
		}
	}
	return ctx.Err()
}

type contextReaderAt struct {
	ctx context.Context
	r   io.ReaderAt
}

func (r contextReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	n, err := r.r.ReadAt(p, off)
	if err == io.EOF && n == len(p) {
		err = nil
	}
	if err != nil {
		return n, &streamReadError{err}
	}
	if n != len(p) {
		return n, &streamReadError{io.ErrUnexpectedEOF}
	}
	return n, nil
}

type streamReadError struct{ error }

func (e *streamReadError) Unwrap() error { return e.error }

// A decoder or printability check can stop before a buffered reader returns
// its pending error. Preserve source failures even when the run is rejected.
type runSourceReader struct {
	io.Reader
	err error
}

func (r *runSourceReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

// variantFile opens only after a decoder has useful output to write.
type variantFile struct {
	file *os.File
	n    int64
	bad  int64
}

func (v *variantFile) Write(p []byte) (int, error) {
	if v.file == nil {
		f, err := os.CreateTemp("", "pleno-dlp-decoded-*")
		if err != nil {
			return 0, err
		}
		v.file = f // CreateTemp creates mode 0600.
	}
	n, err := v.file.Write(p)
	v.n += int64(n)
	v.bad += countNonPrintable(p[:n])
	return n, err
}

func (v *variantFile) close() error {
	if v.file == nil {
		return nil
	}
	return errors.Join(v.file.Close(), os.Remove(v.file.Name()))
}

func printableCounts(n, bad int64) bool {
	return n > 0 && bad <= n-int64(float64(n)*printableThreshold)
}

func countNonPrintable(p []byte) int64 {
	var bad int64
	for _, c := range p {
		if !(c >= 0x20 && c <= 0x7e) && c != '\t' && c != '\n' && c != '\r' {
			bad++
		}
	}
	return bad
}

func walkDecoded(ctx context.Context, input io.ReaderAt, size int64, source string, visit func(string, io.ReaderAt, int64) error) (err error) {
	v := &variantFile{}
	defer func() { err = errors.Join(err, v.close()) }()
	if source == "base64" || source == "hex" {
		err = decodeStreamRuns(ctx, input, size, source == "base64", v)
	} else {
		var eligible bool
		source, eligible, err = streamEncoding(input, size, source)
		if err != nil || !eligible {
			return err
		}
		writer := bufio.NewWriterSize(v, 32*1024)
		err = transformStream(input, size, source, writer)
		if err == nil {
			err = writer.Flush()
		}
	}
	if err != nil {
		return err
	}
	if v.n > 0 && ((source == "base64" || source == "hex") || printableCounts(v.n, v.bad)) {
		return visit(source, v.file, v.n)
	}
	return nil
}

func streamEncoding(input io.ReaderAt, size int64, source string) (string, bool, error) {
	if source == "utf16" {
		var prefix [128]byte
		n, err := input.ReadAt(prefix[:min(size, int64(len(prefix)))], 0)
		if err != nil && err != io.EOF {
			return source, false, err
		}
		if n < 4 {
			return source, false, nil
		}
		le, ok := utf16Encoding(prefix[:n])
		if le {
			return "utf16le", ok, nil
		}
		return "utf16be", ok, nil
	}
	// Preserve the existing adjacent-escape eligibility gate across reads.
	var buf [64*1024 + 11]byte
	carry := 0
	reader := io.NewSectionReader(input, 0, size)
	for {
		n, err := reader.Read(buf[carry:])
		data := buf[:carry+n]
		if (source == "percent" && hasPercentEscapePair(data)) || (source == "unicode-escape" && hasUnicodeEscapePair(data)) {
			return source, true, nil
		}
		if err != nil {
			if err == io.EOF {
				return source, false, nil
			}
			return source, false, err
		}
		carry = min(11, len(data))
		copy(buf[:carry], data[len(data)-carry:])
	}
}

func transformStream(input io.ReaderAt, size int64, source string, out *bufio.Writer) error {
	r := bufio.NewReaderSize(io.NewSectionReader(input, 0, size), 32*1024)
	for {
		need := 1
		if source == "utf16le" || source == "utf16be" {
			need = 2
		}
		p, err := r.Peek(need)
		if err != nil {
			if err == io.EOF {
				return nil // UTF-16's trailing odd byte is ignored by Variants.
			}
			return err
		}
		switch source {
		case "percent":
			c := p[0]
			if c == '%' {
				q, _ := r.Peek(3)
				if len(q) == 3 && isHexByte(q[1]) && isHexByte(q[2]) {
					c, need = hexValue(q[1])<<4|hexValue(q[2]), 3
				}
			} else if c == '+' {
				c = ' '
			}
			err = out.WriteByte(c)
		case "unicode-escape":
			c := p[0]
			q, _ := r.Peek(6)
			if len(q) == 6 && q[0] == '\\' && q[1] == 'u' {
				if hi, ok := parseHex4(q[2:6]); ok {
					value := rune(hi)
					need = 6
					pair, _ := r.Peek(12)
					if hi >= 0xD800 && hi <= 0xDBFF && len(pair) == 12 && pair[6] == '\\' && pair[7] == 'u' {
						if lo, ok := parseHex4(pair[8:12]); ok && lo >= 0xDC00 && lo <= 0xDFFF {
							value, need = utf16.DecodeRune(rune(hi), rune(lo)), 12
						}
					}
					_, err = out.WriteRune(value)
				} else {
					err = out.WriteByte(q[0])
				}
			} else {
				err = out.WriteByte(c)
			}
		default:
			unit := func(b []byte) uint16 {
				if source == "utf16le" {
					return uint16(b[0]) | uint16(b[1])<<8
				}
				return uint16(b[1]) | uint16(b[0])<<8
			}
			value := rune(unit(p))
			if value >= 0xD800 && value <= 0xDBFF {
				q, _ := r.Peek(4)
				if len(q) == 4 && unit(q[2:]) >= 0xDC00 && unit(q[2:]) <= 0xDFFF {
					value, need = utf16.DecodeRune(value, rune(unit(q[2:]))), 4
				} else if len(q) == 4 {
					value = utf8.RuneError
				}
			}
			if value != '\uFEFF' {
				_, err = out.WriteRune(value)
			}
		}
		if err != nil {
			return err
		}
		if _, err := r.Discard(need); err != nil {
			return err
		}
	}
}

// Keep the byte predicates shared with the buffered decoder, but classify a
// stream byte with one lookup instead of repeating range checks in the hot loop.
var streamRunBytes = func() (table [2][256]bool) {
	for i := range table[0] {
		table[0][i] = isHexByte(byte(i))
		table[1][i] = isBase64Byte(byte(i))
	}
	return
}()

func decodeStreamRuns(ctx context.Context, input io.ReaderAt, size int64, b64 bool, output *variantFile) error {
	var scan [64 * 1024]byte
	var decode [32 * 1024]byte
	out := bufio.NewWriterSize(output, len(decode))
	hasOutput := false
	start := int64(-1)
	var alphabet byte
	minimum := int64(minHexRun)
	validBytes := &streamRunBytes[0]
	if b64 {
		minimum = minBase64Run
		validBytes = &streamRunBytes[1]
	}
	flush := func(end int64) error {
		if start < 0 || end-start < minimum {
			start = -1
			return nil
		}
		var encoding *base64.Encoding
		if b64 {
			var padding [2]byte
			n, err := input.ReadAt(padding[:min(int64(2), size-end)], end)
			if err != nil && err != io.EOF {
				return err
			}
			pad := 0
			for pad < n && padding[pad] == '=' {
				pad++
			}
			end += int64(pad)
			encoding = base64Encoding(padding[:pad], alphabet)
		}
		var runInput *runSourceReader
		newReader := func() io.Reader {
			runInput = &runSourceReader{Reader: io.NewSectionReader(input, start, end-start)}
			var r io.Reader = runInput
			if end-start > int64(len(decode)) {
				// The standard decoders read about 1 KiB at a time; coalesce
				// those reads only for runs large enough to use the buffer.
				r = bufio.NewReaderSize(r, len(decode))
			}
			if b64 {
				return base64.NewDecoder(encoding, r)
			}
			return hex.NewDecoder(r)
		}
		upperBound := (end - start) / 2
		if b64 {
			upperBound = (end - start) * 3 / 4
		}
		counter := &printCounter{badBudget: upperBound - int64(float64(upperBound)*printableThreshold)}
		_, err := io.CopyBuffer(counter, newReader(), decode[:])
		if runInput.err != nil {
			return runInput.err
		}
		if err != nil {
			var readErr *streamReadError
			if errors.As(err, &readErr) {
				return err
			}
			var corrupt base64.CorruptInputError
			var invalid hex.InvalidByteError
			if errors.As(err, &corrupt) || errors.As(err, &invalid) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, errNonPrintable) {
				start = -1
				return nil
			}
			return err
		}
		if printableCounts(counter.n, counter.bad) {
			if hasOutput {
				if err := out.WriteByte('\n'); err != nil {
					return err
				}
			}
			_, err := io.CopyBuffer(out, newReader(), decode[:])
			if runInput.err != nil {
				return runInput.err
			}
			if err != nil {
				return err
			}
			hasOutput = true
		}
		start = -1
		return nil
	}
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		block := scan[:min(size-offset, int64(len(scan)))]
		n, err := input.ReadAt(block, offset)
		if err != nil {
			return err
		}
		if n != len(block) {
			return io.ErrUnexpectedEOF
		}
		for i, c := range block {
			if validBytes[c] {
				if start < 0 {
					start, alphabet = offset+int64(i), 0
				}
				if c == '-' || c == '_' {
					alphabet = 1
				} else if c == '+' || c == '/' {
					alphabet = 0
				}
			} else if start >= 0 {
				end := offset + int64(i)
				if end-start >= minimum {
					if err := flush(end); err != nil {
						return err
					}
				} else {
					start = -1
				}
			}
		}
		offset += int64(n)
	}
	if err := flush(size); err != nil {
		return err
	}
	return out.Flush()
}

var errNonPrintable = errors.New("decoder: non-printable run")

type printCounter struct{ n, bad, badBudget int64 }

func (c *printCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	c.bad += countNonPrintable(p)
	if c.bad > c.badBudget {
		return len(p), errNonPrintable
	}
	return len(p), nil
}
