package archive

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"errors"
	"io"
	"regexp"
	"unicode/utf16"
)

// PDF text extraction without a full object model: every stream is located
// by its stream/endstream keywords, FlateDecode streams are inflated under a
// per-stream cap, and string operands are collected from content streams,
// object streams, and the uncompressed body (document info, annotations,
// form values). Strings inside one TJ array are concatenated so kerning
// adjustments do not split a token; text-positioning operators end a line.
// Fonts with custom CMaps are not mapped back to Unicode.

var pdfMagic = []byte("%PDF-")

const pdfMaxStreamBytes = 32 << 20

var (
	pdfStreamKeyword = regexp.MustCompile(`stream\r?\n`)
	pdfFilterFlate   = regexp.MustCompile(`/Filter\s*(\[\s*)?/(FlateDecode|Fl)\b`)
	pdfFilterAny     = regexp.MustCompile(`/Filter\b`)
)

func extractPDF(data []byte, out *textBuffer) error {
	if !bytes.HasPrefix(data, pdfMagic) {
		return errors.New("not a PDF document")
	}
	var body bytes.Buffer // non-stream bytes
	pos := 0
	var errs []error
	for pos < len(data) && !out.overflow {
		loc := pdfStreamKeyword.FindIndex(data[pos:])
		if loc == nil {
			break
		}
		kwStart, start := pos+loc[0], pos+loc[1]
		// "endstream" also matches; only a keyword after a dictionary counts.
		if kwStart >= 3 && string(data[kwStart-3:kwStart]) == "end" {
			pos = start
			continue
		}
		end := bytes.Index(data[start:], []byte("endstream"))
		if end < 0 {
			body.Write(data[pos:kwStart])
			errs = append(errs, errors.New("unterminated stream"))
			pos = len(data)
			break
		}
		dictStart := bytes.LastIndex(data[pos:kwStart], []byte("obj"))
		if dictStart < 0 {
			dictStart = 0
		}
		dict := data[pos+dictStart : kwStart]
		body.Write(data[pos:kwStart])
		raw := bytes.TrimRight(data[start:start+end], "\r\n")
		pos = start + end + len("endstream")
		switch {
		case pdfFilterFlate.Match(dict):
			inflated, err := pdfInflate(raw)
			if len(inflated) > 0 {
				pdfStrings(inflated, out)
			}
			if err != nil {
				errs = append(errs, err)
			}
		case !pdfFilterAny.Match(dict):
			pdfStrings(raw, out)
		}
	}
	if pos < len(data) {
		body.Write(data[pos:])
	}
	pdfStrings(body.Bytes(), out)
	if len(errs) > 0 && out.buf.Len() == 0 {
		return errors.Join(errs...)
	}
	return nil
}

func pdfInflate(raw []byte) ([]byte, error) {
	var r io.Reader
	if zr, err := zlib.NewReader(bytes.NewReader(raw)); err == nil {
		r = zr
	} else {
		r = flate.NewReader(bytes.NewReader(raw))
	}
	b, err := io.ReadAll(io.LimitReader(r, pdfMaxStreamBytes+1))
	if len(b) > pdfMaxStreamBytes {
		return b[:pdfMaxStreamBytes], errors.New("PDF stream exceeds inflate cap")
	}
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return b, err
	}
	return b, nil
}

// pdfStrings tokenizes PDF syntax and writes string operands.
func pdfStrings(data []byte, out *textBuffer) {
	var line bytes.Buffer
	inArray := 0
	flush := func() {
		if line.Len() > 0 {
			out.write(line.Bytes())
			out.writeByte('\n')
			line.Reset()
		}
	}
	for i := 0; i < len(data) && !out.overflow; {
		c := data[i]
		switch {
		case c == '%':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		case c == '(':
			s, n := pdfLiteral(data[i:])
			line.Write(pdfDecodeText(s))
			i += n
			if inArray == 0 {
				line.WriteByte(' ')
			}
		case c == '<' && i+1 < len(data) && data[i+1] == '<':
			i += 2
		case c == '>' && i+1 < len(data) && data[i+1] == '>':
			i += 2
		case c == '<':
			end := bytes.IndexByte(data[i:], '>')
			if end < 0 {
				i = len(data)
				break
			}
			line.Write(pdfDecodeText(pdfHex(data[i+1 : i+end])))
			if inArray == 0 {
				line.WriteByte(' ')
			}
			i += end + 1
		case c == '[':
			inArray++
			i++
		case c == ']':
			if inArray > 0 {
				inArray--
			}
			i++
		case isPDFRegular(c):
			j := i
			for j < len(data) && isPDFRegular(data[j]) {
				j++
			}
			switch string(data[i:j]) {
			case "ET", "Td", "TD", "T*", "Tm", "'", `"`, "endobj", "BT":
				flush()
			}
			i = j
		default:
			i++
		}
	}
	flush()
}

func isPDFRegular(c byte) bool {
	switch c {
	case ' ', '\t', '\r', '\n', '\f', 0, '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return false
	}
	return true
}

// pdfLiteral decodes a balanced literal string starting at '(' and returns
// the decoded bytes and the number of input bytes consumed.
func pdfLiteral(data []byte) ([]byte, int) {
	var out []byte
	depth := 0
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch c {
		case '(':
			if depth > 0 {
				out = append(out, c)
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				return out, i + 1
			}
			out = append(out, c)
		case '\\':
			i++
			if i >= len(data) {
				return out, i
			}
			switch e := data[i]; e {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\r':
				if i+1 < len(data) && data[i+1] == '\n' {
					i++
				}
			case '\n':
			default:
				if e >= '0' && e <= '7' {
					v := 0
					k := 0
					for ; k < 3 && i+k < len(data) && data[i+k] >= '0' && data[i+k] <= '7'; k++ {
						v = v*8 + int(data[i+k]-'0')
					}
					i += k - 1
					out = append(out, byte(v))
				} else {
					out = append(out, e)
				}
			}
		default:
			out = append(out, c)
		}
	}
	return out, len(data)
}

func pdfHex(data []byte) []byte {
	var out []byte
	var hi byte
	half := false
	for _, c := range data {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue
		}
		if half {
			out = append(out, hi<<4|v)
		} else {
			hi = v
		}
		half = !half
	}
	if half {
		out = append(out, hi<<4)
	}
	return out
}

// pdfDecodeText converts UTF-16BE strings (BOM FE FF) to UTF-8.
func pdfDecodeText(b []byte) []byte {
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		b = b[2:]
		units := make([]uint16, len(b)/2)
		for i := range units {
			units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
		}
		return []byte(string(utf16.Decode(units)))
	}
	return b
}
