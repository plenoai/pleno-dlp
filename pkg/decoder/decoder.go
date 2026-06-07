// Package decoder expands a chunk into the original plus useful decoded variants.
package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
)

const minBase64Run = 32

const minHexRun = 40

const printableThreshold = 0.8

// percentEncoded matches a substring containing at least two %xx escapes.
var percentEncoded = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)

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
	return out
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
