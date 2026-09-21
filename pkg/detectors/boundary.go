package detectors

import (
	"bytes"
	"regexp"
)

// FindAllLeftWordBoundary returns regexp matches whose left edge is not
// preceded by an ASCII RE2 word byte. Callers keep any trailing \b in the
// expression so the standard library still enforces the right edge.
func FindAllLeftWordBoundary(re *regexp.Regexp, data []byte) [][]int {
	indices := re.FindAllIndex(data, -1)
	write := 0
	for _, index := range indices {
		if index[0] > 0 && isRE2WordByte(data[index[0]-1]) {
			continue
		}
		indices[write] = index
		write++
	}
	return indices[:write]
}

// HasWordRunCandidate reports whether data contains a prefix followed by a
// complete ASCII word-byte run of totalLen bytes. It is only a necessary-shape
// check; callers must still run their detector regex to decide whether the
// candidate is a finding.
func HasWordRunCandidate(data []byte, prefix string, totalLen int) bool {
	if len(prefix) == 0 || totalLen < len(prefix) || len(data) < totalLen {
		return false
	}

	prefixBytes := []byte(prefix)
	for offset := 0; offset+len(prefixBytes) <= len(data); {
		relative := bytes.Index(data[offset:], prefixBytes)
		if relative < 0 {
			return false
		}
		start := offset + relative
		offset = start + 1
		if start > 0 && isRE2WordByte(data[start-1]) {
			continue
		}

		end := start + totalLen
		if end > len(data) {
			continue
		}
		plausible := true
		for _, c := range data[start+len(prefixBytes) : end] {
			if !isRE2WordByte(c) {
				plausible = false
				break
			}
		}
		if plausible {
			return true
		}
	}
	return false
}

func isRE2WordByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}
