package detectors

import (
	"regexp"
	"strings"
)

// NearKeywords reports whether any keyword in keywords appears within radius
// bytes of the match span [start, end) in the pre-lowercased string lower.
// Covers the ~270 "Variant A" detectors that use a contextKeywords slice.
func NearKeywords(lower string, start, end, radius int, keywords []string) bool {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range keywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// NearPattern reports whether armRe matches within radius bytes of the match
// span [start, end) in the pre-lowercased string lower.
// Covers the ~115 "Variant B" hardened detectors that use an arm regex.
func NearPattern(lower string, start, end, radius int, armRe *regexp.Regexp) bool {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}
