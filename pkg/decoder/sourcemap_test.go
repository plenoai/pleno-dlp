package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"unicode/utf16"
)

func TestSourceSpanRoundTrip(t *testing.T) {
	const secret = "AKIAIOSFODNN7EXAMPLE"
	u16 := func(s string, le bool) []byte {
		var b []byte
		for _, u := range utf16.Encode([]rune(s)) {
			if le {
				b = append(b, byte(u), byte(u>>8))
			} else {
				b = append(b, byte(u>>8), byte(u))
			}
		}
		return b
	}
	esc := "\\" + "u0041" + "\\" + "u004B"
	plain := "prefix key=" + secret + " suffix text"
	cases := []struct {
		source string
		data   []byte
		want   string // encoded form of secret that the span must cover
	}{
		{"percent", []byte("line1\nq=%41%4B" + "IAIOSFODNN7EXAMPLE&x=a+b\n"), "%41%4BIAIOSFODNN7EXAMPLE"},
		{"unicode-escape", []byte(`x="` + esc + `IAIOSFODNN7EXAMPLE"`), esc + "IAIOSFODNN7EXAMPLE"},
		{"base64", []byte("a: " + base64.StdEncoding.EncodeToString([]byte("zzzz zzzz zzzz zzzz zzzz zzzz")) + "\nb: " + base64.StdEncoding.EncodeToString([]byte(plain)) + "\n"), base64.StdEncoding.EncodeToString([]byte(plain))},
		{"hex", []byte("h=" + hex.EncodeToString([]byte(plain)) + ";"), hex.EncodeToString([]byte(plain))},
		{"utf16le", append([]byte{0xFF, 0xFE}, u16(plain, true)...), ""},
		{"utf16be", u16(plain, false), ""},
	}
	for _, tc := range cases {
		t.Run(tc.source, func(t *testing.T) {
			var v *Variant
			for _, got := range Variants(tc.data) {
				if got.Source == tc.source {
					v = &got
				}
			}
			if v == nil {
				t.Fatalf("no %s variant", tc.source)
			}
			idx := bytes.Index(v.Data, []byte(secret))
			if idx < 0 {
				t.Fatalf("secret not in decoded %q", v.Data)
			}
			s, e, ok := SourceSpan(tc.source, tc.data, idx, idx+len(secret))
			if !ok || s < 0 || e > len(tc.data) || s >= e {
				t.Fatalf("span = %d,%d,%v", s, e, ok)
			}
			if tc.want != "" {
				w := bytes.Index(tc.data, []byte(tc.want))
				if s < w || e > w+len(tc.want) {
					t.Fatalf("span [%d,%d) outside encoded run [%d,%d)", s, e, w, w+len(tc.want))
				}
				if tc.source == "percent" || tc.source == "unicode-escape" {
					if s != w || e != w+len(tc.want) {
						t.Fatalf("span [%d,%d) want exact [%d,%d)", s, e, w, w+len(tc.want))
					}
				}
			} else {
				// UTF-16: each ASCII rune is two source bytes.
				if e-s != 2*len(secret) {
					t.Fatalf("utf16 span width = %d, want %d", e-s, 2*len(secret))
				}
			}
		})
	}
	if _, _, ok := SourceSpan("rot13", []byte("x"), 0, 1); ok {
		t.Fatal("unknown source must not map")
	}
	if _, _, ok := SourceSpan("percent", []byte("%41%42"), 5, 9); ok {
		t.Fatal("out-of-range span must not map")
	}
}
