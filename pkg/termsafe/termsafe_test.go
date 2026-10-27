package termsafe

import (
	"bytes"
	"errors"
	"testing"
)

func TestString(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"csi":      {"a\x1b[2Jb", `a\x1b[2Jb`},
		"osc":      {"\x1b]8;;http://x\x07link", `\x1b]8;;http://x\x07link`},
		"c1 csi":   {"a\u009b31m", `a\x9b31m`},
		"bidi":     {"evil\u202etxt.exe\u2066", `evil\u202etxt.exe\u2066`},
		"newlines": {"a\nb\r\nc\u2028d", `a\nb\r\nc\u2028d`},
		"tab":      {"a\tb", `a\tb`},
		"invalid":  {"a\xffb", `a\xffb`},
		"unicode":  {"日本語/ファイル.go café 🔑", "日本語/ファイル.go café 🔑"},
		"plain":    {"src/main.go:12", "src/main.go:12"},
	}
	for name, c := range cases {
		if got := String(c.in); got != c.want {
			t.Errorf("%s: String(%q) = %q, want %q", name, c.in, got, c.want)
		}
	}
}

func TestFprintf(t *testing.T) {
	var b bytes.Buffer
	Fprintf(&b, "repo %s: %v %d\n", "x\x1b[1A", errors.New("bad\nFAKE"), 3)
	if want := "repo x\\x1b[1A: bad\\nFAKE 3\n"; b.String() != want {
		t.Fatalf("got %q want %q", b.String(), want)
	}
}
