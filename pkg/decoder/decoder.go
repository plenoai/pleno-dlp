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

// base64Run matches a candidate base64 substring. Both std and url-safe
// alphabets are unioned. Padding is optional because url-safe base64 in
// the wild often omits it.
var base64Run = regexp.MustCompile(`[A-Za-z0-9+/_-]{32,}={0,2}`)

// hexRun matches a hex run. Lower- or upper-case but not mixed (mixed
// case in the same run is overwhelmingly indicative of base64, not hex).
var hexRun = regexp.MustCompile(`(?:[a-f0-9]{40,}|[A-F0-9]{40,})`)

// percentEncoded matches a substring containing at least two %xx escapes.
// Single isolated escapes (e.g. literal "%20" in a comment) aren't worth
// the decode pass — they're almost never how a secret is hidden.
var percentEncoded = regexp.MustCompile(`(?:%[0-9A-Fa-f]{2}){2,}`)

// Variants returns the original chunk plus any decoded forms produced by
// inspecting data for embedded base64 / percent / hex runs. The original
// is always the first element so callers may iterate without a special
// case for "no decode applied".
func Variants(data []byte) [][]byte {
	out := [][]byte{data}

	if v := decodeBase64(data); v != nil {
		out = append(out, v)
	}
	if v := decodePercent(data); v != nil {
		out = append(out, v)
	}
	if v := decodeHex(data); v != nil {
		out = append(out, v)
	}
	return out
}

// decodeBase64 walks every base64-shaped run, decodes it, and returns the
// concatenation of all printable decode results. Returns nil when nothing
// decoded into something printable. We try std first, fall back to
// url-safe — std fails fast on `+`/`/` mismatch, the cheaper check.
func decodeBase64(data []byte) []byte {
	matches := base64Run.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, m := range matches {
		decoded, ok := tryBase64(m)
		if !ok {
			continue
		}
		if !mostlyPrintable(decoded) {
			continue
		}
		// Separate runs with a newline so a regex anchored on `\b` still
		// finds matches that started at the boundary of a decoded blob.
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(decoded)
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

func tryBase64(s []byte) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		dst := make([]byte, enc.DecodedLen(len(s)))
		n, err := enc.Decode(dst, s)
		if err == nil && n > 0 {
			return dst[:n], true
		}
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
// decodes. Mixed-case runs are excluded by the regex; that's intentional —
// they're nearly always misclassified base64.
func decodeHex(data []byte) []byte {
	matches := hexRun.FindAll(data, -1)
	if len(matches) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for _, m := range matches {
		dst := make([]byte, hex.DecodedLen(len(m)))
		n, err := hex.Decode(dst, m)
		if err != nil {
			continue
		}
		decoded := dst[:n]
		if !mostlyPrintable(decoded) {
			continue
		}
		if buf.Len() > 0 {
			buf.WriteByte('\n')
		}
		buf.Write(decoded)
	}
	if buf.Len() == 0 {
		return nil
	}
	return buf.Bytes()
}

// mostlyPrintable returns true when at least printableThreshold of the
// bytes fall in the printable ASCII range (0x20–0x7e) or are common
// whitespace (\t, \n, \r). Empty input returns false — a zero-byte
// "decode" is never useful to forward.
func mostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	good := 0
	for _, c := range b {
		switch {
		case c >= 0x20 && c <= 0x7e:
			good++
		case c == '\t' || c == '\n' || c == '\r':
			good++
		}
	}
	return float64(good)/float64(len(b)) >= printableThreshold
}
