package decoder

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
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

func TestPercentDecoderRequiresAdjacentEscapes(t *testing.T) {
	variants := Variants([]byte("first=%41 and second=%42"))
	for _, v := range variants {
		if v.Source == "percent" {
			t.Fatal("separated percent escapes should not produce a variant")
		}
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

func makeUTF16LE(s string, bom bool) []byte {
	var buf bytes.Buffer
	if bom {
		buf.WriteByte(0xFF)
		buf.WriteByte(0xFE)
	}
	for _, r := range s {
		lo := byte(uint16(r) & 0xFF)
		hi := byte(uint16(r) >> 8)
		buf.WriteByte(lo)
		buf.WriteByte(hi)
	}
	return buf.Bytes()
}

func makeUTF16BE(s string, bom bool) []byte {
	var buf bytes.Buffer
	if bom {
		buf.WriteByte(0xFE)
		buf.WriteByte(0xFF)
	}
	for _, r := range s {
		hi := byte(uint16(r) >> 8)
		lo := byte(uint16(r) & 0xFF)
		buf.WriteByte(hi)
		buf.WriteByte(lo)
	}
	return buf.Bytes()
}

func TestUTF16LE_BOM_DetectedAndDecoded(t *testing.T) {
	secret := "CONFIG_CREDENTIAL=pleno-dlp-utf16-fixture-roundtrip-test-0000000000a"
	data := makeUTF16LE(secret, true)
	variants := Variants(data)

	if !containsBytes(variants, []byte(secret)) {
		t.Fatalf("UTF-16LE with BOM: expected decoded secret in variants; got %d variants", len(variants))
	}
	for _, v := range variants {
		if containsBytes([]Variant{v}, []byte(secret)) && v.Source != "utf16le" {
			t.Errorf("expected Source=utf16le, got %q", v.Source)
		}
	}
}

func TestUTF16BE_BOM_DetectedAndDecoded(t *testing.T) {
	secret := "CONFIG_CREDENTIAL=pleno-dlp-utf16-fixture-roundtrip-test-0000000000a"
	data := makeUTF16BE(secret, true)
	variants := Variants(data)

	if !containsBytes(variants, []byte(secret)) {
		t.Fatalf("UTF-16BE with BOM: expected decoded secret in variants; got %d variants", len(variants))
	}
	for _, v := range variants {
		if containsBytes([]Variant{v}, []byte(secret)) && v.Source != "utf16be" {
			t.Errorf("expected Source=utf16be, got %q", v.Source)
		}
	}
}

func TestUTF16LE_NoBOM_Heuristic(t *testing.T) {
	secret := "CONFIG_CREDENTIAL=pleno-dlp-utf16-fixture-roundtrip-test-0000000000a"
	data := makeUTF16LE(secret, false)
	variants := Variants(data)

	if !containsBytes(variants, []byte(secret)) {
		t.Fatalf("UTF-16LE without BOM heuristic: expected decoded secret in variants; got %d", len(variants))
	}
}

func TestUTF16_ShortDataSkipped(t *testing.T) {
	data := []byte{0xFF, 0xFE} // BOM but no content
	variants := Variants(data)
	for _, v := range variants {
		if v.Source == "utf16le" || v.Source == "utf16be" {
			t.Errorf("short UTF-16 data should not produce a variant; got Source=%q", v.Source)
		}
	}
}

func TestUnicodeEscape_DecodesEscapedSecret(t *testing.T) {
	// Build the chunk programmatically so the editor cannot collapse \uXXXX.
	// "secret" as \u-escaped ASCII: each char → \uXXXX.
	escaped := unicodeEscapeASCII("secret")
	chunk := []byte(`{"api_key":"` + escaped + `"}`)
	variants := Variants(chunk)

	if !containsBytes(variants, []byte("secret")) {
		t.Fatalf("expected unicode-escape variant to contain decoded value; got %d variants", len(variants))
	}
	var sawSource bool
	for _, v := range variants {
		if v.Source == "unicode-escape" {
			sawSource = true
		}
	}
	if !sawSource {
		t.Fatal("expected a variant with Source=unicode-escape")
	}
}

func TestUnicodeEscape_SurrogatePair(t *testing.T) {
	// U+1F600 (😀) as surrogate pair repeated twice.
	// Surround with enough ASCII so mostlyPrintable passes after decode.
	prefix := "this is a long config comment that makes the decoded form mostly printable "
	pair := "\\uD83D\\uDE00"
	chunk := []byte(prefix + pair + " " + prefix + pair)
	variants := Variants(chunk)
	decoded := "\U0001F600"
	if !containsBytes(variants, []byte(decoded)) {
		t.Fatalf("expected surrogate pair to decode to U+1F600; got %d variants", len(variants))
	}
}

func TestUnicodeEscape_NoVariantWhenNoEscapes(t *testing.T) {
	chunk := []byte("plain text without any unicode escapes at all here")
	variants := Variants(chunk)
	for _, v := range variants {
		if v.Source == "unicode-escape" {
			t.Errorf("unexpected unicode-escape variant for plain text")
		}
	}
}

func TestUnicodeEscapeRequiresAdjacentEscapes(t *testing.T) {
	chunk := []byte(`prefix=\u0041 separator \u0042`)
	variants := Variants(chunk)
	for _, v := range variants {
		if v.Source == "unicode-escape" {
			t.Fatal("separated unicode escapes should not produce a variant")
		}
	}
}

func TestBase64MultipleRunsKeepOrder(t *testing.T) {
	first := []byte(strings.Repeat("first printable payload ", 3))
	second := []byte(strings.Repeat("second printable payload ", 3))
	chunk := []byte(base64.StdEncoding.EncodeToString(first) + "!" + base64.StdEncoding.EncodeToString(second))
	variants := Variants(chunk)
	for _, v := range variants {
		if v.Source == "base64" {
			want := append(append([]byte{}, first...), '\n')
			want = append(want, second...)
			if !bytes.Equal(v.Data, want) {
				t.Fatalf("base64 variant = %q, want %q", v.Data, want)
			}
			return
		}
	}
	t.Fatal("expected base64 variant")
}

func TestVariantsWithScratchEquivalentToVariants(t *testing.T) {
	raw := []byte(strings.Repeat("base64 payload with credential-shaped text ", 3))
	chunk := []byte("payload=" + base64.StdEncoding.EncodeToString(raw) + "&value=%41%42")
	want := Variants(chunk)
	got := VariantsWithScratch(chunk, make([]byte, 0, len(raw)+1))
	if len(got) != len(want) {
		t.Fatalf("variant count = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Source != want[i].Source || !bytes.Equal(got[i].Data, want[i].Data) {
			t.Fatalf("variant %d = (%q, %q), want (%q, %q)", i, got[i].Source, got[i].Data, want[i].Source, want[i].Data)
		}
	}
}

func TestVariantsWithScratchMultipleRunsAndRejectedRun(t *testing.T) {
	first := []byte(strings.Repeat("first printable payload ", 3))
	second := []byte(strings.Repeat("second printable payload ", 3))
	rejected := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 64))
	chunk := []byte(base64.StdEncoding.EncodeToString(first) + "!" + rejected + "@" + base64.StdEncoding.EncodeToString(second))
	scratch := make([]byte, 0, len(first)+len(second)+1)
	variants := VariantsWithScratch(chunk, scratch)
	for _, v := range variants {
		if v.Source != "base64" {
			continue
		}
		want := append(append([]byte{}, first...), '\n')
		want = append(want, second...)
		if !bytes.Equal(v.Data, want) {
			t.Fatalf("base64 variant = %q, want %q", v.Data, want)
		}
		return
	}
	t.Fatal("expected base64 variant")
}

func TestVariantsWithScratchUsesProvidedCapacity(t *testing.T) {
	raw := []byte(strings.Repeat("scratch-backed payload ", 3))
	chunk := []byte(base64.StdEncoding.EncodeToString(raw))
	scratch := make([]byte, 0, base64DecodedLen(chunk))
	variants := VariantsWithScratch(chunk, scratch)
	for _, v := range variants {
		if v.Source != "base64" {
			continue
		}
		if len(v.Data) == 0 || &v.Data[0] != &scratch[:cap(scratch)][0] {
			t.Fatal("base64 result did not use sufficient scratch capacity")
		}
		return
	}
	t.Fatal("expected base64 variant")
}

func TestVariantsWithScratchCanReuseBuffer(t *testing.T) {
	first := []byte(strings.Repeat("first reusable payload ", 3))
	second := []byte(strings.Repeat("second reusable payload ", 3))
	scratch := make([]byte, 0, base64DecodedLen([]byte(base64.StdEncoding.EncodeToString(second))))
	_ = VariantsWithScratch([]byte(base64.StdEncoding.EncodeToString(first)), scratch)
	got := VariantsWithScratch([]byte(base64.StdEncoding.EncodeToString(second)), scratch)
	for _, v := range got {
		if v.Source == "base64" {
			if !bytes.Equal(v.Data, second) {
				t.Fatalf("reused base64 result = %q, want %q", v.Data, second)
			}
			return
		}
	}
	t.Fatal("expected base64 variant")
}

func TestVariantsWithScratchRejectedRunDoesNotEmitEmptyVariant(t *testing.T) {
	data := []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 64)))
	variants := VariantsWithScratch(data, make([]byte, 0, 1))
	for _, v := range variants {
		if v.Source == "base64" {
			t.Fatalf("rejected base64 run emitted empty variant: %q", v.Data)
		}
	}
}

func TestVariantsWithScratchInsufficientCapacityOwnsResult(t *testing.T) {
	raw := []byte(strings.Repeat("owned after scratch exhaustion ", 4))
	chunk := []byte(base64.StdEncoding.EncodeToString(raw))
	scratch := make([]byte, 0, 8)
	variants := VariantsWithScratch(chunk, scratch)
	var decoded []byte
	for _, v := range variants {
		if v.Source == "base64" {
			decoded = v.Data
			break
		}
	}
	if decoded == nil {
		t.Fatal("expected base64 variant")
	}
	backing := scratch[:cap(scratch)]
	for i := range backing {
		backing[i] = '!'
	}
	if !bytes.Equal(decoded, raw) {
		t.Fatalf("owned base64 result changed after scratch reuse: got %q, want %q", decoded, raw)
	}
}

func TestUTF16UnpairedSurrogateUsesReplacementRune(t *testing.T) {
	data := []byte{0x00, 0xD8, 'A', 0x00}
	got := decodeUTF16(data, true)
	if want := []byte("\uFFFDA"); !bytes.Equal(got, want) {
		t.Fatalf("decodeUTF16 = %q, want %q", got, want)
	}
}

// unicodeEscapeASCII encodes each character of s as a \uXXXX sequence.
// Used in tests to construct chunks with literal escape sequences without
// relying on the editor to keep them as-is.
func unicodeEscapeASCII(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		fmt.Fprintf(&b, "\\u%04X", c)
	}
	return b.String()
}

func BenchmarkVariantsCold(b *testing.B) {
	data := []byte(strings.Repeat("ordinary source text with no encoded runs or credential-shaped data.\n", 512))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Variants(data)
	}
}

func BenchmarkVariantsBase64(b *testing.B) {
	raw := []byte(strings.Repeat("encoded log line with a stable printable payload and no binary bytes.\n", 4096))
	data := []byte(base64.StdEncoding.EncodeToString(raw))
	b.ReportMetric(float64(len(data)), "input-bytes")
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Variants(data)
	}
}

func BenchmarkVariantsPercent(b *testing.B) {
	data := []byte("token=" + strings.Repeat("%41", 4096) + "&" + strconv.Itoa(1))
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Variants(data)
	}
}
