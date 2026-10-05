package termutil

import "testing"

func TestSanitizeStripsControlSequences(t *testing.T) {
	cases := map[string]string{
		"plain text":                    "plain text",
		"\x1b[2Jclear":                   "?[2Jclear",
		"pre\x1b]8;;http://x\x07post":   "?]8;;http://x?post",
		"forged\nrevoke OK: tok":        "forged?revoke OK: tok",
		"tab\tsep":                      "tab?sep",
		"bidi\u202Eevil":             "bidi?evil",
		"日本語はそのまま":                   "日本語はそのまま",
		"provider error: \x1b[31mred\x1b[0m": "provider error: ?[31mred?[0m",
	}
	for in, want := range cases {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
