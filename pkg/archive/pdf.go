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
// Page content shown with fonts that carry a /ToUnicode CMap is decoded
// through that CMap first (pdfcmap.go); those streams are then skipped here.

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
	handled := pdfPageText(indexPDFObjects(data), out)
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
		case handled[start]:
		case pdfFilterFlate.Match(dict):
			inflated, err := pdfInflate(raw)
			if len(inflated) > 0 && !bytes.Contains(inflated, []byte("begincmap")) {
				pdfStrings(inflated, out)
			}
			if err != nil {
				errs = append(errs, err)
			}
		case !pdfFilterAny.Match(dict) && !bytes.Contains(raw, []byte("begincmap")):
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
func pdfStrings(data []byte, out *textBuffer) { pdfStringsWithFonts(data, nil, out) }

// pdfStringsWithFonts decodes string operands through the ToUnicode CMap of
// the font most recently selected by Tf, when one is known.
func pdfStringsWithFonts(data []byte, fonts map[string]*pdfCMap, out *textBuffer) {
	var line bytes.Buffer
	inArray := 0
	var lastName, prevTok, lastTmY string
	var font *pdfCMap
	// Marked content carrying /ActualText replaces the glyphs it encloses
	// (Skia maps spaces and ligatures this way), so those glyphs are skipped.
	dictDepth, mcDepth, suppressAt := 0, 0, 0
	pendingActual := false
	var actualText []byte
	decode := func(b []byte) []byte {
		if dictDepth > 0 {
			if fonts != nil && lastName == "ActualText" {
				// Written where the replaced glyphs are shown, after any
				// line-breaking positioning that precedes them.
				pendingActual = true
				actualText = pdfDecodeText(b)
				return nil
			}
			return pdfDecodeText(b)
		}
		if suppressAt > 0 {
			return nil
		}
		if font != nil {
			return font.decode(b)
		}
		return pdfDecodeText(b)
	}
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
			line.Write(decode(s))
			i += n
			if inArray == 0 && fonts == nil {
				line.WriteByte(' ')
			}
		case c == '<' && i+1 < len(data) && data[i+1] == '<':
			dictDepth++
			i += 2
		case c == '>' && i+1 < len(data) && data[i+1] == '>':
			if dictDepth > 0 {
				dictDepth--
			}
			i += 2
		case c == '<':
			end := bytes.IndexByte(data[i:], '>')
			if end < 0 {
				i = len(data)
				break
			}
			line.Write(decode(pdfHex(data[i+1 : i+end])))
			if inArray == 0 && fonts == nil {
				line.WriteByte(' ')
			}
			i += end + 1
		case c == '/' && fonts != nil:
			j := i + 1
			for j < len(data) && isPDFRegular(data[j]) {
				j++
			}
			lastName = string(data[i+1 : j])
			i = j
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
			op := string(data[i:j])
			if fonts != nil {
				// Page text is positioned glyph by glyph; a horizontal-only
				// move (tx 0 Td) continues the line instead of splitting a
				// token into one-character lines.
				switch {
				case op == "Tf":
					font = fonts[lastName]
				case (op == "Td" || op == "TD") && prevTok == "0":
					i = j
					continue
				case op == "Tm":
					// A new text matrix on the same baseline (font switch
					// mid-line) continues the line.
					sameLine := prevTok == lastTmY
					lastTmY, prevTok = prevTok, op
					if sameLine {
						i = j
						continue
					}
				case op == "BDC" || op == "BMC":
					mcDepth++
					if pendingActual && suppressAt == 0 {
						suppressAt = mcDepth
					}
					pendingActual = false
				case op == "Tj" || op == "TJ" || op == "'" || op == `"`:
					if suppressAt > 0 && actualText != nil {
						line.Write(actualText)
						actualText = nil
					}
				case op == "EMC":
					if suppressAt == mcDepth {
						suppressAt = 0
						line.Write(actualText)
						actualText = nil
					}
					if mcDepth > 0 {
						mcDepth--
					}
				}
				prevTok = op
			}
			switch op {
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
