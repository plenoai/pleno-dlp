// Package decoder expands a chunk into the original plus useful decoded variants.
package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
	"unicode/utf16"
	"unicode/utf8"
)

const minBase64Run = 32

const minHexRun = 40

const printableThreshold = 0.8

// percentEncoded matches a substring containing at least two %xx escapes.
var percentEncoded = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)

// unicodeEscaped matches a substring containing at least two \uXXXX sequences.
var unicodeEscaped = regexp.MustCompile(`(?:\\u[0-9A-Fa-f]{4}){2,}`)

// Variant pairs a decoded byte slice with the decoder that produced it.
type Variant struct {
	Source string
	Data   []byte
}

// Variants returns the original chunk followed by decoded forms worth rescanning.
func Variants(data []byte) []Variant {
	out := []Variant{{Data: data}}

	if hasBase64Run(data) {
		if v := decodeBase64(data); v != nil {
			out = append(out, Variant{Source: "base64", Data: v})
		}
	}
	if hasPercentRun(data) {
		if v := decodePercent(data); v != nil {
			out = append(out, Variant{Source: "percent", Data: v})
		}
	}
	if hasHexRun(data) {
		if v := decodeHex(data); v != nil {
			out = append(out, Variant{Source: "hex", Data: v})
		}
	}
	if src, v := tryUTF16(data); v != nil {
		out = append(out, Variant{Source: src, Data: v})
	}
	if unicodeEscaped.Match(data) {
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
	s := string(data)
	out := make([]byte, 0, len(data))
	i := 0
	for i < len(s) {
		if i+5 < len(s) && s[i] == '\\' && s[i+1] == 'u' {
			hi, ok := parseHex4(s[i+2 : i+6])
			if !ok {
				out = append(out, s[i])
				i++
				continue
			}
			r := rune(hi)
			consumed := 6
			// Surrogate pair handling.
			if r >= 0xD800 && r <= 0xDBFF && i+11 < len(s) && s[i+6] == '\\' && s[i+7] == 'u' {
				lo, ok2 := parseHex4(s[i+8 : i+12])
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
			out = append(out, s[i])
			i++
		}
	}
	if bytes.Equal(out, data) || !mostlyPrintable(out) {
		return nil
	}
	return out
}

func parseHex4(s string) (uint16, bool) {
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
	// Definitive BOM check.
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
		return true, true // odd positions are NUL → LE
	}
	if float64(evenNUL)/float64(half) >= threshold {
		return false, true // even positions are NUL → BE
	}
	return false, false
}

// decodeUTF16 transcodes a UTF-16 byte slice (with or without BOM) to UTF-8.
// If isLE is true the input is treated as little-endian; otherwise big-endian.
// The BOM codepoint (U+FEFF) is stripped from the output.
func decodeUTF16(data []byte, isLE bool) []byte {
	// Strip BOM if present.
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

	// Decode pairs into runes, handling surrogate pairs.
	u16 := make([]uint16, len(data)/2)
	for i := range u16 {
		lo, hi := data[i*2], data[i*2+1]
		if isLE {
			u16[i] = uint16(lo) | uint16(hi)<<8
		} else {
			u16[i] = uint16(hi) | uint16(lo)<<8
		}
	}
	runes := utf16.Decode(u16)

	// Encode runes to UTF-8.
	var buf bytes.Buffer
	buf.Grow(len(runes) * 3 / 2)
	tmp := make([]byte, utf8.UTFMax)
	for _, r := range runes {
		if r == '\uFEFF' { // skip BOM rune
			continue
		}
		n := utf8.EncodeRune(tmp, r)
		buf.Write(tmp[:n])
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// hasBase64Run reports whether data contains a plausible base64 run.
func hasBase64Run(data []byte) bool {
	run := 0
	for _, c := range data {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '_' || c == '-' {
			run++
			if run >= minBase64Run {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// hasHexRun reports whether data contains a plausible hex run.
func hasHexRun(data []byte) bool {
	var lowerRun, upperRun int
	for _, c := range data {
		switch {
		case c >= 'a' && c <= 'f', c >= '0' && c <= '9':
			lowerRun++
			upperRun = 0
			if lowerRun >= minHexRun {
				return true
			}
		case c >= 'A' && c <= 'F':
			upperRun++
			lowerRun = 0
			if upperRun >= minHexRun {
				return true
			}
		default:
			lowerRun, upperRun = 0, 0
		}
	}
	return false
}

// hasPercentRun reports whether data contains at least two percent escapes.
func hasPercentRun(data []byte) bool {
	n := 0
	for _, c := range data {
		if c == '%' {
			n++
			if n >= 2 {
				return true
			}
		}
	}
	return false
}

// decodeBase64 returns the printable decodes from all base64-like runs.
func decodeBase64(data []byte) []byte {
	var buf bytes.Buffer
	walkBase64Runs(data, func(run []byte) {
		decoded, ok := tryBase64(run)
		if !ok {
			return
		}
		if !mostlyPrintable(decoded) {
			return
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(decoded)
	})
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// walkBase64Runs finds maximal base64-like runs plus trailing padding.
func walkBase64Runs(data []byte, fn func([]byte)) {
	start := -1
	for i := 0; i < len(data); i++ {
		c := data[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '+' || c == '/' || c == '_' || c == '-' {
			if start < 0 {
				start = i
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
				fn(data[start : end+pad])
			}
			start = -1
		}
	}
	if start >= 0 && len(data)-start >= minBase64Run {
		fn(data[start:])
	}
}

func tryBase64(s []byte) ([]byte, bool) {
	// Pick the right encoding from the run's own bytes instead of
	// trying all four. Std vs URL alphabet is mutually exclusive on
	// the '+/' vs '-_' axis; padded vs raw is determined by trailing
	// '='. Profiling on the real-OSS workload showed the four-try
	// loop dominated the decoder by allocating one DecodedLen slice
	// per attempt, with three of every four attempts failing.
	var alphabet byte // 0 = std, 1 = url-safe
	for _, c := range s {
		switch c {
		case '-', '_':
			alphabet = 1
		case '+', '/':
			alphabet = 0
			// std markers are decisive; '-'/'_' could appear inside
			// a run that already had '+'/'/', so don't break on alphabet=1
			// until the scan completes.
		}
	}
	padded := len(s) > 0 && s[len(s)-1] == '='
	var enc *base64.Encoding
	switch {
	case alphabet == 1 && padded:
		enc = base64.URLEncoding
	case alphabet == 1:
		enc = base64.RawURLEncoding
	case padded:
		enc = base64.StdEncoding
	default:
		enc = base64.RawStdEncoding
	}
	dst := make([]byte, enc.DecodedLen(len(s)))
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
	dst = dst[:cap(dst)]
	n, err = enc.Decode(dst, s)
	if err == nil && n > 0 {
		return dst[:n], true
	}
	return nil, false
}

// decodePercent fires when the chunk contains at least one cluster of
// %xx escapes. We pass the entire chunk through url.QueryUnescape so a
// secret pasted as a query string survives the round-trip even when it
// straddles literal characters.
func decodePercent(data []byte) []byte {
	if !percentEncoded.Match(data) {
		return nil
	}
	decoded, err := url.QueryUnescape(string(data))
	if err != nil {
		return nil
	}
	if decoded == string(data) {
		return nil
	}
	if !mostlyPrintable([]byte(decoded)) {
		return nil
	}
	return []byte(decoded)
}

// decodeHex finds hex runs >= 40 chars and concatenates their printable
// decodes. Mixed-case runs are excluded; that's intentional — they're
// nearly always misclassified base64. Run detection is a linear byte
// scan to skip the RE2 setup cost the original hexRun regex paid on
// every chunk.
func decodeHex(data []byte) []byte {
	var buf bytes.Buffer
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
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(decoded)
	})
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// walkHexRuns invokes fn for every maximal run of >=minHexRun bytes
// drawn from a single-case hex alphabet (a-f0-9 or A-F0-9, not mixed).
// Mirrors the hexRun regex without RE2.
func walkHexRuns(data []byte, fn func([]byte)) {
	const (
		caseNone byte = iota
		caseLower
		caseUpper
	)
	start := -1
	cur := caseNone
	flush := func(end int) {
		if start >= 0 && end-start >= minHexRun {
			fn(data[start:end])
		}
		start = -1
		cur = caseNone
	}
	for i := 0; i < len(data); i++ {
		c := data[i]
		var kind byte
		switch {
		case c >= '0' && c <= '9':
			kind = cur // digits don't force a case
		case c >= 'a' && c <= 'f':
			kind = caseLower
		case c >= 'A' && c <= 'F':
			kind = caseUpper
		default:
			flush(i)
			continue
		}
		if start < 0 {
			start = i
			if kind == caseNone {
				kind = caseLower // bias digits to lower; will pivot on first letter
			}
			cur = kind
			continue
		}
		if kind == caseNone {
			// First letter wasn't seen yet; treat as compatible.
			continue
		}
		if cur == caseNone {
			cur = kind
			continue
		}
		if kind != cur {
			// Mixed case: end the previous run, start a fresh one at i.
			flush(i)
			start = i
			cur = kind
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
