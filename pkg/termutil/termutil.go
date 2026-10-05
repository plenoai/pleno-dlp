// Package termutil guards human-facing terminal output against control
// sequences smuggled inside remote- or scan-derived strings.
package termutil

import (
	"strings"
	"unicode"
)

// Sanitize replaces every non-printing rune with '?' — control, format,
// and surrogate runes per unicode.IsPrint — so ANSI/OSC escapes, bidi
// overrides, and raw newlines carried by remote content cannot inject
// terminal control output or forge output lines on stderr.
func Sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
}
