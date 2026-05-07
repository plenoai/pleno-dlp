package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
)

func TestVariantsAlwaysIncludesOriginal(t *testing.T) {
	original := []byte("nothing to decode here")
	got := Variants(original)
	if len(got) == 0 || !bytes.Equal(got[0].Data, original) || got[0].Source != "" {
		t.Fatalf("expected original first with empty Source; got %+v", got)
	}
}

func TestBase64HiddenAKIA(t *testing.T) {
	// AKIAIOSFODNN7EXAMPLE base64-encoded inside a normal-looking string.
	akia := "AKIAIOSFODNN7EXAMPLE"
	hidden := base64.StdEncoding.EncodeToString([]byte("Authorization: " + akia))
	chunk := []byte("env: AUTH=" + hidden + " other=stuff")

	variants := Variants(chunk)
	if !containsBytes(variants, []byte(akia)) {
		t.Fatalf("expected variants to contain decoded AKIA; got %d variants", len(variants))
	}
}

func TestPercentEncodedJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"
	chunk := []byte("token=" + url.QueryEscape(jwt))

	variants := Variants(chunk)
	if !containsBytes(variants, []byte(jwt)) {
		t.Fatalf("expected percent-decoded JWT; got %d variants", len(variants))
	}
}

func TestHexEncodedAccessKey(t *testing.T) {
	akia := []byte("AKIAIOSFODNN7EXAMPLE")
	chunk := []byte("payload=" + hex.EncodeToString(akia))

	variants := Variants(chunk)
	if !containsBytes(variants, akia) {
		t.Fatalf("expected hex-decoded AKIA; got %d variants", len(variants))
	}
}

func TestNoDecodeWhenInputClean(t *testing.T) {
	// Plain text with no encoded runs of useful length should yield only
	// the original.
	chunk := []byte("hello world; nothing encoded here")
	variants := Variants(chunk)
	if len(variants) != 1 {
		t.Fatalf("expected 1 variant (original only); got %d", len(variants))
	}
}

func TestBase64DecodeRejectsBinaryNoise(t *testing.T) {
	// 0xFF-only payload base64-encodes to a long printable string but
	// decodes back to bytes that fail the printable threshold. Decoder
	// must drop it rather than forwarding garbage to detectors.
	bin := bytes.Repeat([]byte{0xff}, 64)
	chunk := []byte(base64.StdEncoding.EncodeToString(bin))
	variants := Variants(chunk)
	for i, v := range variants {
		if i == 0 {
			continue // original always present
		}
		if bytes.Contains(v.Data, bin) {
			t.Fatalf("decoder forwarded binary-only decode (variant %d)", i)
		}
	}
}

func TestMixedCaseHexRejected(t *testing.T) {
	// AbCdEf... mixed-case is almost always base64, not hex. The hex
	// path must skip it; the base64 path may still decode, but we
	// assert the hex-decoded result (which would be garbage here) is
	// not part of the output.
	mixed := strings.Repeat("aF", 40)
	chunk := []byte(mixed)
	variants := Variants(chunk)
	for i, v := range variants {
		if i == 0 {
			continue
		}
		if bytes.Contains(v.Data, bytes.Repeat([]byte{0xaf}, 40)) {
			t.Fatalf("hex decoder leaked non-printable bytes: variant %d", i)
		}
	}
}

func TestVariantsTagSource(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	hidden := base64.StdEncoding.EncodeToString([]byte("Authorization: " + akia))
	variants := Variants([]byte("AUTH=" + hidden))
	var sawBase64 bool
	for _, v := range variants {
		if v.Source == "base64" {
			sawBase64 = true
		}
	}
	if !sawBase64 {
		t.Fatal("expected at least one variant with Source=\"base64\"")
	}
}

func TestMostlyPrintable(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"all ascii", []byte("hello world"), true},
		{"with tab newline", []byte("a\tb\nc"), true},
		{"all binary", bytes.Repeat([]byte{0x00}, 16), false},
		{"60% printable below threshold", []byte{'a', 'b', 'c', 0x00, 0x00}, false},
		{"80% printable at threshold", []byte{'a', 'b', 'c', 'd', 0x00}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := mostlyPrintable(tc.in); got != tc.want {
				t.Fatalf("mostlyPrintable(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func containsBytes(variants []Variant, needle []byte) bool {
	for _, v := range variants {
		if bytes.Contains(v.Data, needle) {
			return true
		}
	}
	return false
}
