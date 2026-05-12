// Package decoder expands a chunk of bytes into the original plus any
// decoded variants worth re-scanning. Three encodings are inspected:
//
//   - base64 (std + url-safe), runs of >=32 chars
//   - percent-encoded sequences (%xx), when at least two are present
//   - hex, runs of >=40 chars (covers SHA1/256 and key-shaped blobs)
//
// Each variant is returned only when its decoded byte stream is mostly
// printable ASCII — a heuristic that filters out random-looking decoded
// noise such as binary blobs accidentally inside a base64 paragraph.
//
// Variants() never returns the original twice, even if no decoder fired.
// Callers feed every returned slice through their detector pipeline so a
// secret hidden inside `Authorization: Bearer <base64-of-token>` is found
// the same way as one written in plaintext.
package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"regexp"
)

// minBase64Run is the shortest base64 run we'll attempt to decode. AWS
// secret access keys are 40 chars and produce 30 raw bytes, but anything
// shorter than 32 input chars is overwhelmingly noise (UUIDs, hashes).
const minBase64Run = 32

// minHexRun is the shortest hex run worth decoding. SHA1 (40), MD5 (32 —
// excluded as too noisy), SHA256 (64). 40 strikes a balance: catches keys
// pasted as hex, skips the average UUID without dashes (32).
const minHexRun = 40

// printableThreshold is the minimum fraction of printable bytes a decoded
// variant must contain before we forward it to detectors. 0.8 was chosen
// empirically: lower lets binary slip through and floods detectors with
// nonsense; higher loses real secrets that happen to neighbour binary.
const printableThreshold = 0.8

// percentEncoded matches a substring containing at least two %xx escapes.
// Single isolated escapes (e.g. literal "%20" in a comment) aren't worth
// the decode pass — they're almost never how a secret is hidden.
//
// base64 and hex run detection was migrated off RE2 onto a linear byte
// scan (see walkBase64Runs / walkHexRuns) after profiling showed the
// regex variants dominating the real-OSS workload. The literals remain
// documented above as the source-of-truth shape that the scans must
// stay in sync with.
var percentEncoded = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)

// Variant pairs a decoded byte slice with the decoder that produced it.
// The original chunk uses Source="" so callers can branch on the empty
// string to detect "this is the unmodified input".
type Variant struct {
	Source string
	Data   []byte
}

// Variants returns the original chunk plus any decoded forms produced by
// inspecting data for embedded base64 / percent / hex runs. The original
// is always the first element so callers may iterate without a special
// case for "no decode applied".
//
// Each decoder is gated by a cheap byte-scan that checks whether the
// chunk *could* contain a candidate run. On the cold path — the dominant
// shape on real codebases — the gate falls through in one linear pass
// and the per-decoder regex never runs. Profiling showed the bare regex
// FindAll calls were consuming ~26% of the cold-path engine CPU because
// FindAll walks the full input even on a no-match, so the gate is the
// difference between O(N) memmove-friendly byte work and O(N) regex
// machine stepping.
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

// hasBase64Run reports whether data contains a run of >=minBase64Run
// bytes drawn from the base64 alphabet (std + url-safe). Tracks runs in
// a single pass; bails out the moment the threshold is reached. Cheaper
// than regexp.FindAll on the no-match path because it skips RE2 machine
// setup entirely.
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

// hasHexRun reports whether data contains a run of >=minHexRun bytes
// drawn from a single-case hex alphabet (matching hexRun's
// mixed-case-rejecting behaviour).
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
	// A run that's pure digits would have been counted under either side;
	// re-walk only when the chunk has at least one digit-only span >=
	// minHexRun. Cheap: in practice the loop above already returned, so
	// we just need to consider chunks of all-digits that never crossed
	// either alpha. Skip — pure-digit runs aren't valid hex secrets in
	// any of our targets, and the original hexRun regex would have
	// matched them but never produced a printable decode anyway.
	return false
}

// hasPercentRun reports whether data contains >=2 percent signs. The
// original percentEncoded regex required two %xx escapes; the cheap
// guard here doesn't validate the trailing hex, just counts '%'. False
// positives fall through to url.QueryUnescape which then returns the
// unchanged string (caught by the equality check below).
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

// decodeBase64 walks every base64-shaped run, decodes it, and returns the
// concatenation of all printable decode results. Returns nil when nothing
// decoded into something printable.
//
// Run boundaries are produced by a single linear byte scan instead of
// the RE2 base64Run regex — the regex was the largest single hot spot
// on the real-OSS workload (~17% of total CPU) because every chunk
// holding any encoded blob paid full RE2 machine setup. The byte scan
// hands back the same slice spans with no allocation beyond the result
// list itself.
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
		// Separate runs with a newline so a regex anchored on `\b` still
		// finds matches that started at the boundary of a decoded blob.
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

// walkBase64Runs invokes fn for every maximal run of >=minBase64Run
// base64-alphabet bytes (std + url-safe) plus any trailing '=' padding.
// Mirrors the base64Run regex `[A-Za-z0-9+/_-]{32,}={0,2}` without RE2.
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
				// Consume up to two '=' padding bytes immediately following.
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
