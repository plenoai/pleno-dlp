package termutil

import "testing"

func TestSanitizeStripsControlSequences(t *testing.T) {
	check := func(in, want string) {
		t.Helper()
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
	check("plain text", "plain text")
	check("\x1b[2Jclear", "?[2Jclear")
	check("pre\x1b]8;;http://x\x07post", "pre?]8;;http://x?post")
	check("forged\nrevoke OK: tok", "forged?revoke OK: tok")
	check("tab\tsep", "tab?sep")
	check("bidi\u202Eevil", "bidi?evil")
	check("日本語はそのまま", "日本語はそのまま")
	check("provider error: \x1b[31mred\x1b[0m", "provider error: ?[31mred?[0m")
}
