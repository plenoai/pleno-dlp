package detectors

import (
	"strings"
)

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

func NearPattern(lower string, start, end, radius int, armRe *Regexp) bool {
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
