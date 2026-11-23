package archive

import (
	"fmt"
	"strings"
	"testing"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/korean"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/traditionalchinese"
	"golang.org/x/text/encoding/unicode"
)

func encodeWith(t *testing.T, e encoding.Encoding, s string) string {
	t.Helper()
	b, err := e.NewEncoder().Bytes([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%X", b)
}

// Each font's string is encoded by golang.org/x/text, an oracle independent
// of the Adobe tables, and must come back as the original text.
func TestExtractPDFPredefinedCMaps(t *testing.T) {
	utf16be := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)
	cases := []struct {
		cmap string
		enc  encoding.Encoding
		text string
	}{
		{"90ms-RKSJ-H", japanese.ShiftJIS, "秘密トークンABC"},
		{"90ms-RKSJ-V", japanese.ShiftJIS, "縦書き鍵"},
		{"EUC-H", japanese.EUCJP, "日本語の鍵"},
		{"GBK-EUC-H", simplifiedchinese.GBK, "密钥令牌"},
		{"GB-EUC-H", simplifiedchinese.HZGB2312, ""}, // placeholder, replaced below
		{"B5pc-H", traditionalchinese.Big5, "權杖密碼"},
		{"KSCms-UHC-H", korean.EUCKR, "토큰비밀"},
		{"KSC-EUC-H", korean.EUCKR, "한국어"},
		{"UniJIS-UCS2-H", utf16be, "ユニコード鍵"},
		{"UniGB-UTF16-V", utf16be, "密钥𠀋"},
		{"UniKS-UTF8-H", unicode.UTF8, "토큰"},
	}
	cases[4] = struct {
		cmap string
		enc  encoding.Encoding
		text string
	}{"GBK-EUC-V", simplifiedchinese.GBK, "中文"}
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	var res, content strings.Builder
	for i, c := range cases {
		res.WriteString(fmt.Sprintf("/F%d %d 0 R ", i, 10+i))
		content.WriteString(fmt.Sprintf("BT /F%d 9 Tf <%s> Tj ET\n", i, encodeWith(t, c.enc, c.text)))
	}
	b.WriteString(pdfObj(3, "<< /Type /Page /Resources << /Font << "+res.String()+">> >> /Contents 4 0 R >>", ""))
	b.WriteString(pdfObj(4, "", content.String()))
	for i, c := range cases {
		b.WriteString(pdfObj(10+i, fmt.Sprintf("<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /%s /DescendantFonts [99 0 R] >>", c.cmap), ""))
	}
	b.WriteString(pdfObj(99, "<< /Type /Font /Subtype /CIDFontType0 >>", ""))
	b.WriteString("%%EOF\n")
	entries, err := walkEntries(t, "t.pdf", []byte(b.String()), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	got := strings.Join(strings.Fields(entries["t.pdf#text"]), "")
	for _, c := range cases {
		if !strings.Contains(got, c.text) {
			t.Errorf("%s: %q missing from %q", c.cmap, c.text, got)
		}
	}
}

func TestPredefinedCMapTables(t *testing.T) {
	for name, ordering := range predefinedCMapOrdering {
		for _, suffix := range []string{"-H", "-V"} {
			cm := decodePredefCMap(name + suffix)
			if name == "H" {
				cm = decodePredefCMap(map[string]string{"-H": "H", "-V": "V"}[suffix])
			}
			if cm == nil || len(cm.cids) == 0 {
				t.Fatalf("%s%s (%s): no table", name, suffix, ordering)
			}
		}
	}
	h, v := decodePredefCMap("90ms-RKSJ-H"), decodePredefCMap("90ms-RKSJ-V")
	if h.cids[2<<32|0x8141] == v.cids[2<<32|0x8141] {
		t.Fatal("-V must override vertical codes")
	}
	if h.cids[1<<32|0x41] != 264 || h.lens[0x41] != 1 || h.lens[0x88] != 2 {
		t.Fatalf("RKSJ: A=%d lens %d %d", h.cids[1<<32|0x41], h.lens[0x41], h.lens[0x88])
	}
	if r := cidOrderingTable("Japan1")[264]; r != 'A' {
		t.Fatalf("half-width CID 264 = %U, want U+0041 (UCS2-HW fallback)", r)
	}
	for _, n := range []string{"Identity-H", "Foo-H", "UniJIS-UCS2-H", ""} {
		if decodePredefCMap(n) != nil {
			t.Fatalf("%q must have no legacy table", n)
		}
	}
}

func FuzzPredefinedCMapDecode(f *testing.F) {
	f.Add("90ms-RKSJ-H", []byte("\x88\xea\x41\x82"))
	f.Add("UniGB-UTF16-H", []byte("\xd8\x40\xdc\x0b\x4e"))
	f.Add("CNS-EUC-V", []byte("\x8e\xa2\xa1\xa1"))
	f.Fuzz(func(t *testing.T, name string, b []byte) {
		font := pdfType0Predefined([]byte("<< /Encoding /" + name + " >>"))
		if font == nil {
			return
		}
		out := font.decode(b)
		if !utf8Valid(out) {
			t.Fatalf("invalid UTF-8 from %s", name)
		}
	})
}

func utf8Valid(b []byte) bool { return strings.ToValidUTF8(string(b), "�") == string(b) }
