package detectors

import "regexp"

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

func isRE2WordByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}
