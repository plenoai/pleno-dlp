// Package termsafe neutralises terminal control content in untrusted values
// before they reach human-readable output (table sink, stderr diagnostics).
// Paths, redacted secrets, provider errors and clone progress all originate
// in scanned repositories or remote services; raw CSI/OSC sequences, bidi
// overrides or embedded line breaks could rewrite the terminal or hide
// findings. Machine formats (JSON, SARIF) must NOT use this package — they
// stay byte-accurate.
package termsafe

import (
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// String returns s with every C0/C1 control, DEL, bidi formatting character
// and invalid UTF-8 byte replaced by a visible Go-style escape (\x1b, \n,
// \u202e). Ordinary printable Unicode passes through unchanged.
func String(s string) string {
	if isClean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case unsafeRune(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

func isClean(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || unsafeRune(r) {
			return false
		}
		i += size
	}
	return true
}

func unsafeRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f,
		r >= 0x202a && r <= 0x202e,
		r >= 0x2066 && r <= 0x2069,
		r == 0x2028, r == 0x2029:
		return true
	}
	return false
}

// Args sanitizes string, error and fmt.Stringer arguments so they can be
// formatted with a trusted format string. Other values are returned as-is.
func Args(args []any) []any {
	out := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			out[i] = String(v)
		case error:
			out[i] = String(v.Error())
		case fmt.Stringer:
			out[i] = String(v.String())
		case []byte:
			out[i] = String(string(v))
		default:
			out[i] = a
		}
	}
	return out
}

// Fprintf is fmt.Fprintf with untrusted arguments sanitized. The format
// string is trusted and may contain its own newlines.
func Fprintf(w io.Writer, format string, args ...any) (int, error) {
	return fmt.Fprintf(w, format, Args(args)...)
}
