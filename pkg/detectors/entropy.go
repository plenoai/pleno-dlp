// Shannon entropy helpers used by provider-specific detectors to
// reject low-information candidate tokens.
//
// Generic high-entropy detection (`pkg/detectors/generic`) keeps its
// own inlined copy of the formula on purpose — see the doc comment
// over `shannonEntropy` in that package. We deliberately do NOT move
// that copy here; the generic detector evolved independently and its
// thresholds are tuned against a specific corpus.
//
// This file exists so provider-specific detectors with intentionally
// loose token regexes (drift / lever / pumble / totango / sift, etc.)
// can apply a cheap second-pass gate against runs of zeros, repeated
// `aaaa…` patterns, and other low-entropy garbage that would
// otherwise sneak past a `[A-Za-z0-9]{32,80}` regex.
//
// Threshold guidance:
//
//	~3.0  bits/char — minimum sane floor for hex strings
//	                  (alphabet of 16 → ceiling ≈ 4.0)
//	~3.5  bits/char — base64url / alnum tokens
//	                  (alphabet of 62-64 → ceiling ≈ 6.0)
//	~4.0  bits/char — generic high-entropy detector default
package detectors

import "math"

// ShannonEntropy returns the bits-per-byte Shannon entropy of s.
// Returns 0 for the empty string. Exported so provider detectors in
// sibling packages can call it.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]int, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

// HasMinEntropy reports whether the Shannon entropy of s meets or
// exceeds the given threshold. Convenience wrapper for the common
// guard pattern.
func HasMinEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) >= threshold
}
