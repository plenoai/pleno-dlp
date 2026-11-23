package decoder

import (
	"encoding/hex"
	"unicode/utf16"
	"unicode/utf8"
)

// segment maps decoded bytes [dec, decEnd) onto original bytes
// [src, srcEnd). Copied text produces identity segments; an escape or an
// encoded run produces one segment whose interior offsets are interpolated.
type segment struct{ dec, decEnd, src, srcEnd int }

// SourceSpan maps the decoded byte range [start, end) of the Variant that
// decoder source produced from data back to the original byte range that
// encodes it. Findings in decoded variants use it to recover the path, line,
// inline pragma, and baseline span of the encoded text (#964).
//
// The mapping is recomputed by replaying the decoder over data, so the scan
// hot path keeps no offset table; only findings in decoded variants pay for
// it. ok is false for an unknown source or a range outside the variant.
func SourceSpan(source string, data []byte, start, end int) (srcStart, srcEnd int, ok bool) {
	if start < 0 || end <= start {
		return 0, 0, false
	}
	var walk func(func(segment) bool)
	switch source {
	case "percent":
		walk = func(fn func(segment) bool) { walkPercentSegments(data, fn) }
	case "unicode-escape":
		walk = func(fn func(segment) bool) { walkUnicodeEscapeSegments(data, fn) }
	case "base64":
		walk = func(fn func(segment) bool) { walkBase64Segments(data, fn) }
	case "hex":
		walk = func(fn func(segment) bool) { walkHexSegments(data, fn) }
	case "utf16le", "utf16be":
		walk = func(fn func(segment) bool) { walkUTF16Segments(data, source == "utf16le", fn) }
	default:
		return 0, 0, false
	}
	foundStart, foundEnd := false, false
	walk(func(s segment) bool {
		if s.decEnd <= s.dec {
			return true
		}
		if !foundStart && start < s.decEnd {
			off := max(start-s.dec, 0)
			srcStart = s.src + off*(s.srcEnd-s.src)/(s.decEnd-s.dec)
			foundStart = true
		}
		if foundStart && s.dec < end {
			off := min(end, s.decEnd) - s.dec
			n, d := off*(s.srcEnd-s.src), s.decEnd-s.dec
			srcEnd = s.src + (n+d-1)/d
			foundEnd = end <= s.decEnd
		}
		return !foundEnd
	})
	if !foundStart || srcEnd <= srcStart {
		return 0, 0, false
	}
	return srcStart, srcEnd, true
}

// walkCopy emits identity segments for runs of copied bytes so a long
// literal stretch costs one callback rather than one per byte.
type copyRun struct {
	dec, src, n int
	fn          func(segment) bool
	stop        bool
}

func (c *copyRun) add(dec, src int) {
	if c.n > 0 && c.dec+c.n == dec && c.src+c.n == src {
		c.n++
		return
	}
	c.flush()
	c.dec, c.src, c.n = dec, src, 1
}

func (c *copyRun) flush() {
	if c.n > 0 && !c.stop {
		c.stop = !c.fn(segment{c.dec, c.dec + c.n, c.src, c.src + c.n})
	}
	c.n = 0
}

func (c *copyRun) emit(s segment) {
	c.flush()
	if !c.stop {
		c.stop = !c.fn(s)
	}
}

// walkPercentSegments mirrors decodePercentCandidate.
func walkPercentSegments(data []byte, fn func(segment) bool) {
	run := copyRun{fn: fn}
	dec := 0
	for i := 0; i < len(data) && !run.stop; i++ {
		if data[i] == '%' && i+2 < len(data) && isHexByte(data[i+1]) && isHexByte(data[i+2]) {
			run.emit(segment{dec, dec + 1, i, i + 3})
			dec++
			i += 2
			continue
		}
		if data[i] == '+' {
			run.emit(segment{dec, dec + 1, i, i + 1})
		} else {
			run.add(dec, i)
		}
		dec++
	}
	run.flush()
}

// walkUnicodeEscapeSegments mirrors decodeUnicodeEscape.
func walkUnicodeEscapeSegments(data []byte, fn func(segment) bool) {
	run := copyRun{fn: fn}
	dec := 0
	for i := 0; i < len(data) && !run.stop; {
		if i+5 < len(data) && data[i] == '\\' && data[i+1] == 'u' {
			hi, ok := parseHex4(data[i+2 : i+6])
			if ok {
				r := rune(hi)
				consumed := 6
				if r >= 0xD800 && r <= 0xDBFF && i+11 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
					lo, ok2 := parseHex4(data[i+8 : i+12])
					if ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
						r = utf16.DecodeRune(r, rune(lo))
						consumed = 12
					}
				}
				n := utf8.RuneLen(r)
				if n < 0 {
					n = len(string(utf8.RuneError))
				}
				run.emit(segment{dec, dec + n, i, i + consumed})
				dec += n
				i += consumed
				continue
			}
		}
		run.add(dec, i)
		dec++
		i++
	}
	run.flush()
}

// walkBase64Segments mirrors decodeBase64WithScratch: accepted runs are
// joined with a single '\n' that maps to no source bytes.
func walkBase64Segments(data []byte, fn func(segment) bool) {
	dec, stop := 0, false
	var buf []byte
	walkBase64RunsMeta(data, func(run []byte, alphabet byte) {
		if stop {
			return
		}
		if n := base64DecodedLen(run); cap(buf) < n {
			buf = make([]byte, n)
		}
		decoded, ok := decodeBase64Into(run, alphabet, buf[:cap(buf)])
		if !ok || !mostlyPrintable(decoded) {
			return
		}
		if dec > 0 {
			dec++
		}
		src := offsetOf(data, run)
		stop = !fn(segment{dec, dec + len(decoded), src, src + len(run)})
		dec += len(decoded)
	})
}

// walkHexSegments mirrors decodeHex.
func walkHexSegments(data []byte, fn func(segment) bool) {
	dec, stop := 0, false
	walkHexRuns(data, func(run []byte) {
		if stop {
			return
		}
		dst := make([]byte, hex.DecodedLen(len(run)))
		n, err := hex.Decode(dst, run)
		if err != nil || !mostlyPrintable(dst[:n]) {
			return
		}
		if dec > 0 {
			dec++
		}
		src := offsetOf(data, run)
		stop = !fn(segment{dec, dec + n, src, src + len(run)})
		dec += n
	})
}

// walkUTF16Segments mirrors decodeUTF16.
func walkUTF16Segments(data []byte, isLE bool, fn func(segment) bool) {
	base := 0
	if len(data) >= 2 && ((isLE && data[0] == 0xFF && data[1] == 0xFE) ||
		(!isLE && data[0] == 0xFE && data[1] == 0xFF)) {
		base = 2
	}
	body := data[base:]
	if len(body)%2 != 0 {
		body = body[:len(body)-1]
	}
	unit := func(i int) uint16 {
		if isLE {
			return uint16(body[i]) | uint16(body[i+1])<<8
		}
		return uint16(body[i+1]) | uint16(body[i])<<8
	}
	dec := 0
	for i := 0; i < len(body); i += 2 {
		u := unit(i)
		r := rune(u)
		width := 2
		if u >= 0xD800 && u <= 0xDBFF && i+3 < len(body) {
			if lo := unit(i + 2); lo >= 0xDC00 && lo <= 0xDFFF {
				r = utf16.DecodeRune(r, rune(lo))
				width = 4
			} else {
				r = utf8.RuneError
			}
		} else if u >= 0xDC00 && u <= 0xDFFF {
			r = utf8.RuneError
		}
		if r == '\uFEFF' {
			i += width - 2
			continue
		}
		n := utf8.RuneLen(r)
		if n < 0 {
			n = len(string(utf8.RuneError))
		}
		if !fn(segment{dec, dec + n, base + i, base + i + width}) {
			return
		}
		dec += n
		i += width - 2
	}
}

// offsetOf returns the index of sub inside data; sub must be a subslice.
func offsetOf(data, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	return cap(data) - cap(sub)
}
