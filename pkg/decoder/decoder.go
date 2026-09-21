// Package decoder expands a chunk into the original plus useful decoded variants.
package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"unicode/utf16"
	"unicode/utf8"
)

const minBase64Run = 32

const minHexRun = 40

const printableThreshold = 0.8

// Variant pairs a decoded byte slice with the decoder that produced it.
type Variant struct {
	Source string
	Data   []byte
}

// Variants returns the original chunk followed by decoded forms worth rescanning.
func Variants(data []byte) []Variant {
	return VariantsWithScratch(data, nil)
}

// VariantsWithScratch is Variants with an optional caller-owned scratch
// buffer for the base64 result. When scratch has enough capacity, a returned
// base64 Variant aliases it and is valid only until the caller reuses or
// overwrites scratch. Other decoded variants remain independently owned.
// If scratch is too small, the base64 result is copied into an owned buffer.
// Callers must not pass a scratch buffer that aliases data.
func VariantsWithScratch(data, scratch []byte) []Variant {
	out := []Variant{{Data: data}}

	if v := decodeBase64WithScratch(data, scratch); v != nil {
		out = append(out, Variant{Source: "base64", Data: v})
	}
	if hasPercentEscapePair(data) {
		if v := decodePercentCandidate(data); v != nil {
			out = append(out, Variant{Source: "percent", Data: v})
		}
	}
	if v := decodeHex(data); v != nil {
		out = append(out, Variant{Source: "hex", Data: v})
	}
	if src, v := tryUTF16(data); v != nil {
		out = append(out, Variant{Source: src, Data: v})
	}
	if hasUnicodeEscapePair(data) {
		if v := decodeUnicodeEscape(data); v != nil {
			out = append(out, Variant{Source: "unicode-escape", Data: v})
		}
	}
	return out
}

// decodeUnicodeEscape replaces \uXXXX sequences with their UTF-8 equivalents.
// Surrogate pairs (\uD800–\uDBFF followed by \uDC00–\uDFFF) are combined
// before encoding. Returns nil when the decoded form is not mostly printable
// or is identical to the input.
func decodeUnicodeEscape(data []byte) []byte {
	out := make([]byte, 0, len(data))
	changed := false
	i := 0
	for i < len(data) {
		if i+5 < len(data) && data[i] == '\\' && data[i+1] == 'u' {
			hi, ok := parseHex4(data[i+2 : i+6])
			if !ok {
				out = append(out, data[i])
				i++
				continue
			}
			changed = true
			r := rune(hi)
			consumed := 6
			if r >= 0xD800 && r <= 0xDBFF && i+11 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
				lo, ok2 := parseHex4(data[i+8 : i+12])
				if ok2 && lo >= 0xDC00 && lo <= 0xDFFF {
					r = utf16.DecodeRune(r, rune(lo))
					consumed = 12
				}
			}
			var buf [utf8.UTFMax]byte
			n := utf8.EncodeRune(buf[:], r)
			out = append(out, buf[:n]...)
			i += consumed
		} else {
			out = append(out, data[i])
			i++
		}
	}
	if !changed || !mostlyPrintable(out) {
		return nil
	}
	return out
}

func parseHex4(s []byte) (uint16, bool) {
	if len(s) != 4 {
		return 0, false
	}
	var v uint16
	for _, c := range []byte(s) {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint16(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v |= uint16(c-'A') + 10
		default:
			return 0, false
		}
	}
	return v, true
}

func isBase64Byte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '_' || c == '-'
}

func isHexByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F')
}

func isPercentEscapePair(data []byte) bool {
	return data[0] == '%' && isHexByte(data[1]) && isHexByte(data[2]) &&
		data[3] == '%' && isHexByte(data[4]) && isHexByte(data[5])
}

func hasPercentEscapePair(data []byte) bool {
	for start := 0; start < len(data); {
		rel := bytes.IndexByte(data[start:], '%')
		if rel < 0 {
			return false
		}
		i := start + rel
		if i+5 < len(data) && isPercentEscapePair(data[i:]) {
			return true
		}
		start = i + 1
	}
	return false
}

func isUnicodeEscapePair(data []byte) bool {
	return data[0] == '\\' && data[1] == 'u' && isHexByte(data[2]) &&
		isHexByte(data[3]) && isHexByte(data[4]) && isHexByte(data[5]) &&
		data[6] == '\\' && data[7] == 'u' && isHexByte(data[8]) &&
		isHexByte(data[9]) && isHexByte(data[10]) && isHexByte(data[11])
}

func hasUnicodeEscapePair(data []byte) bool {
	for start := 0; start < len(data); {
		rel := bytes.IndexByte(data[start:], '\\')
		if rel < 0 {
			return false
		}
		i := start + rel
		if i+11 < len(data) && isUnicodeEscapePair(data[i:]) {
			return true
		}
		start = i + 1
	}
	return false
}

// tryUTF16 returns a ("utf16le"|"utf16be", UTF-8 bytes) pair when data looks
// like a UTF-16 encoded file (BOM-sniff first, then heuristic alternating-NUL
// detection). Returns ("", nil) when the data is not UTF-16 or the decoded
// result is not useful.
func tryUTF16(data []byte) (string, []byte) {
	if len(data) < 4 {
		return "", nil
	}
	isLE, detected := utf16Encoding(data)
	if !detected {
		return "", nil
	}
	decoded := decodeUTF16(data, isLE)
	if decoded == nil || !mostlyPrintable(decoded) {
		return "", nil
	}
	if isLE {
		return "utf16le", decoded
	}
	return "utf16be", decoded
}

// utf16Encoding returns (isLE, true) when data begins with a UTF-16 BOM or
// shows an alternating-NUL pattern characteristic of ASCII-dominant UTF-16
// text. Returns (false, false) when no UTF-16 signature is found.
func utf16Encoding(data []byte) (isLE bool, ok bool) {
	if data[0] == 0xFF && data[1] == 0xFE {
		return true, true
	}
	if data[0] == 0xFE && data[1] == 0xFF {
		return false, true
	}

	// Heuristic: if most odd bytes are NUL it is likely UTF-16LE ASCII text;
	// if most even bytes are NUL it is likely UTF-16BE ASCII text.
	// Sample the first 128 bytes (or less) for speed; require even length.
	sample := data
	if len(sample) > 128 {
		sample = sample[:128]
	}
	if len(sample)%2 != 0 {
		sample = sample[:len(sample)-1]
	}
	if len(sample) < 8 {
		return false, false
	}
	half := len(sample) / 2

	var evenNUL, oddNUL int
	for i, b := range sample {
		if b == 0 {
			if i%2 == 0 {
				evenNUL++
			} else {
				oddNUL++
			}
		}
	}
	const threshold = 0.75
	if float64(oddNUL)/float64(half) >= threshold {
		return true, true
	}
	if float64(evenNUL)/float64(half) >= threshold {
		return false, true
	}
	return false, false
}

// LooksLikeUTF16Text cheaply recognizes UTF-16 text for sources that must
// decide whether a NUL-containing input is binary before reading its body.
// It shares the decoder's BOM/alternating-NUL heuristic and printable check;
// callers still pass the original bytes to Variants for the actual decode.
func LooksLikeUTF16Text(data []byte) bool {
	_, decoded := tryUTF16(data)
	return decoded != nil
}

// decodeUTF16 transcodes a UTF-16 byte slice (with or without BOM) to UTF-8.
// If isLE is true the input is treated as little-endian; otherwise big-endian.
// The BOM codepoint (U+FEFF) is stripped from the output.
func decodeUTF16(data []byte, isLE bool) []byte {
	if len(data) >= 2 {
		if (isLE && data[0] == 0xFF && data[1] == 0xFE) ||
			(!isLE && data[0] == 0xFE && data[1] == 0xFF) {
			data = data[2:]
		}
	}
	if len(data)%2 != 0 {
		data = data[:len(data)-1]
	}
	if len(data) == 0 {
		return nil
	}

	// Decode pairs directly into UTF-8. This avoids retaining both the UTF-16
	// units and utf16.Decode's rune slice for the same chunk.
	out := make([]byte, 0, len(data)/2)
	var tmp [utf8.UTFMax]byte
	for i := 0; i < len(data); i += 2 {
		var u uint16
		if isLE {
			u = uint16(data[i]) | uint16(data[i+1])<<8
		} else {
			u = uint16(data[i+1]) | uint16(data[i])<<8
		}
		r := rune(u)
		if u >= 0xD800 && u <= 0xDBFF && i+3 < len(data) {
			var lo uint16
			if isLE {
				lo = uint16(data[i+2]) | uint16(data[i+3])<<8
			} else {
				lo = uint16(data[i+3]) | uint16(data[i+2])<<8
			}
			if lo >= 0xDC00 && lo <= 0xDFFF {
				r = utf16.DecodeRune(r, rune(lo))
				i += 2
			} else {
				r = utf8.RuneError
			}
		} else if u >= 0xDC00 && u <= 0xDFFF {
			r = utf8.RuneError
		}
		if r == '\uFEFF' {
			continue
		}
		n := utf8.EncodeRune(tmp[:], r)
		out = append(out, tmp[:n]...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// decodeBase64WithScratch appends accepted runs in source order. It only
// commits the separator after a run passes decoding and printability checks,
// so rejected runs cannot overwrite or corrupt earlier accepted output.
func decodeBase64WithScratch(data, scratch []byte) []byte {
	var out []byte
	owned := false
	scratch = scratch[:0]
	walkBase64RunsMeta(data, func(run []byte, alphabet byte) {
		needed := base64DecodedLen(run)
		previousLen := len(out)
		separator := 0
		if previousLen > 0 {
			separator = 1
		}
		start := previousLen + separator
		if !owned && start+needed > cap(scratch) {
			out = append([]byte(nil), out...)
			owned = true
		}
		var dst []byte
		if owned {
			out = slices.Grow(out, separator+needed)
			out = out[:start+needed]
			dst = out[start:]
		} else {
			scratch = scratch[:start+needed]
			dst = scratch[start:]
		}
		decoded, ok := decodeBase64Into(run, alphabet, dst)
		if !ok || !mostlyPrintable(decoded) {
			if owned {
				out = out[:previousLen]
			}
			return
		}
		if owned {
			out = out[:start+len(decoded)]
		} else {
			scratch = scratch[:start+len(decoded)]
			out = scratch
		}
		if separator > 0 {
			out[start-1] = '\n'
		}
	})
	if len(out) == 0 {
		return nil
	}
	return out
}

func base64DecodedLen(run []byte) int {
	max := 0
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if n := enc.DecodedLen(len(run)); n > max {
			max = n
		}
	}
	return max
}

// walkBase64RunsMeta also carries the alphabet marker found while locating a
// run, so decoding does not scan every accepted run a second time.
func walkBase64RunsMeta(data []byte, fn func([]byte, byte)) {
	start := -1
	var alphabet byte
	for i := 0; i < len(data); i++ {
		c := data[i]
		if isBase64Byte(c) {
			if start < 0 {
				start = i
				alphabet = 0
			}
			switch c {
			case '-', '_':
				alphabet = 1
			case '+', '/':
				alphabet = 0
			}
			continue
		}
		if start >= 0 {
			end := i
			if i-start >= minBase64Run {
				pad := 0
				for pad < 2 && end+pad < len(data) && data[end+pad] == '=' {
					pad++
				}
				fn(data[start:end+pad], alphabet)
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minBase64Run {
		fn(data[start:], alphabet)
	}
}

func decodeBase64Into(s []byte, alphabet byte, dst []byte) ([]byte, bool) {
	enc := base64Encoding(s, alphabet)
	n, err := enc.Decode(dst, s)
	if err == nil && n > 0 {
		return dst[:n], true
	}
	// Fallback: the heuristic guessed wrong (e.g. a std run that happens
	// to lack '+'/'/' but is padded). Try the complementary encoding so
	// we don't regress on the AKIA-in-base64 test corpus.
	switch enc {
	case base64.StdEncoding:
		enc = base64.RawStdEncoding
	case base64.RawStdEncoding:
		enc = base64.StdEncoding
	case base64.URLEncoding:
		enc = base64.RawURLEncoding
	case base64.RawURLEncoding:
		enc = base64.URLEncoding
	}
	n, err = enc.Decode(dst, s)
	if err == nil && n > 0 {
		return dst[:n], true
	}
	return nil, false
}

func base64Encoding(s []byte, alphabet byte) *base64.Encoding {
	padded := len(s) > 0 && s[len(s)-1] == '='
	if alphabet == 1 {
		if padded {
			return base64.URLEncoding
		}
		return base64.RawURLEncoding
	}
	if padded {
		return base64.StdEncoding
	}
	return base64.RawStdEncoding
}

func decodePercentCandidate(data []byte) []byte {
	decoded := make([]byte, 0, len(data))
	changed := false
	for i := 0; i < len(data); i++ {
		if data[i] == '%' && i+2 < len(data) && isHexByte(data[i+1]) && isHexByte(data[i+2]) {
			decoded = append(decoded, hexValue(data[i+1])<<4|hexValue(data[i+2]))
			i += 2
			changed = true
			continue
		}
		if data[i] == '+' {
			decoded = append(decoded, ' ')
			changed = true
			continue
		}
		decoded = append(decoded, data[i])
	}
	if !changed || len(decoded) == len(data) || !mostlyPrintable(decoded) {
		return nil
	}
	return decoded
}

func hexValue(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}

// decodeHex finds hex runs >= 40 chars and concatenates their printable
// decodes. Mixed-case runs are excluded; that's intentional — they're
// nearly always misclassified base64. Run detection is a linear byte
// scan to skip the RE2 setup cost the original hexRun regex paid on
// every chunk.
func decodeHex(data []byte) []byte {
	var out []byte
	walkHexRuns(data, func(run []byte) {
		dst := make([]byte, hex.DecodedLen(len(run)))
		n, err := hex.Decode(dst, run)
		if err != nil {
			return
		}
		decoded := dst[:n]
		if !mostlyPrintable(decoded) {
			return
		}
		if out == nil {
			out = decoded
			return
		}
		out = append(out, '\n')
		out = append(out, decoded...)
	})
	return out
}

// walkHexRuns invokes fn for every maximal run of >=minHexRun hexadecimal
// bytes. Hex encoding is case-insensitive, so mixed-case runs stay intact.
func walkHexRuns(data []byte, fn func([]byte)) {
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= minHexRun {
			fn(data[start:end])
		}
		start = -1
	}
	for i := 0; i < len(data); i++ {
		if !isHexByte(data[i]) {
			flush(i)
			continue
		}
		if start < 0 {
			start = i
		}
	}
	flush(len(data))
}

// mostlyPrintable returns true when at least printableThreshold of the
// bytes fall in the printable ASCII range (0x20–0x7e) or are common
// whitespace (\t, \n, \r). Empty input returns false — a zero-byte
// "decode" is never useful to forward.
//
// Short-circuits once the bad-byte count exceeds the rejection budget,
// so binary blobs (the common decoder false-positive on SHA-hash and
// base64-documentation noise in source code) bail in a fraction of the
// full scan.
func mostlyPrintable(b []byte) bool {
	n := len(b)
	if n == 0 {
		return false
	}
	// Maximum bad bytes the threshold can tolerate. Once we exceed it,
	// the answer is unconditionally false — no need to keep counting.
	badBudget := n - int(float64(n)*printableThreshold)
	bad := 0
	for _, c := range b {
		switch {
		case c >= 0x20 && c <= 0x7e:
		case c == '\t' || c == '\n' || c == '\r':
		default:
			bad++
			if bad > badBudget {
				return false
			}
		}
	}
	return true
}
