package archive

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode"
)

// testdata/quartz-hant.pdf and quartz-ko.pdf are macOS Quartz PDFContext
// output (cupsfilter of a text file) with CFF CIDFontType0 fonts, Identity-H
// and no ToUnicode: Traditional Chinese set in Hiragino Sans (Adobe-Japan1,
// including the Japan1-6 variant CID 20282 for U+6756) and Korean set in
// Apple SD Gothic Neo (Adobe-Korea1).
func TestExtractPDFQuartzCIDOrderings(t *testing.T) {
	for file, wants := range map[string][]string{
		"testdata/quartz-hant.pdf": {"tw token FIXTURE-QUARTZ-CNS", "繁體中文權杖"},
		"testdata/quartz-ko.pdf":   {"ko token FIXTURE-QUARTZ-KS", "한국어", "토큰"},
	} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		entries, err := walkEntries(t, "q.pdf", data, Limits{})
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		requireEntry(t, entries, "q.pdf#text", wants...)
	}
}

func TestCIDOrderingTables(t *testing.T) {
	for _, tc := range []struct {
		ordering string
		min      int
		cid      uint16
		want     rune
	}{
		{"Japan1", 15000, 1200, '一'},  // listed as U+2F00 and U+4E00: the radical loses
		{"Japan1", 15000, 20282, '杖'}, // variant glyph only in the JIS2004 column
		{"Japan1", 15000, 843, 'あ'},
		{"GB1", 29000, 4559, '中'},
		{"CNS1", 18000, 1, ' '},
		{"Korea1", 17000, 1, ' '},
		{"KR", 21000, 1, ' '},
	} {
		table := cidOrderingTable(tc.ordering)
		if len(table) < tc.min {
			t.Fatalf("%s: %d CIDs, want at least %d", tc.ordering, len(table), tc.min)
		}
		if got := table[tc.cid]; got != tc.want {
			t.Errorf("%s CID %d = %U, want %U", tc.ordering, tc.cid, got, tc.want)
		}
		for cid, r := range table {
			if unicode.Is(unicode.Co, r) {
				t.Errorf("%s CID %d maps to private use %U", tc.ordering, cid, r)
			}
		}
	}
	if cidOrderingTable("Identity") != nil || cidOrderingTable("Manga1") != nil {
		t.Fatal("unregistered orderings must have no table")
	}
}

func TestExtractPDFType0Ordering(t *testing.T) {
	gb := cidOrderingTable("GB1")
	var zhong uint16
	for cid, r := range gb {
		if r == '中' {
			zhong = cid
			break
		}
	}
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	b.WriteString(pdfObj(3, "<< /Type /Page /Resources << /Font << /F1 5 0 R /F2 7 0 R /F3 9 0 R >> >> /Contents 4 0 R >>", ""))
	b.WriteString(pdfObj(4, "", fmt.Sprintf("BT /F1 9 Tf <04B0> Tj ET BT /F2 9 Tf <%04X> Tj ET BT /F3 9 Tf <04B0> Tj ET", zhong)))
	// Japan1 through an indirect CIDSystemInfo.
	b.WriteString(pdfObj(5, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [6 0 R] >>", ""))
	b.WriteString(pdfObj(6, "<< /Type /Font /Subtype /CIDFontType0 /CIDSystemInfo 11 0 R >>", ""))
	b.WriteString(pdfObj(11, "<< /Registry (Adobe) /Ordering (Japan1) /Supplement 6 >>", ""))
	b.WriteString(pdfObj(7, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-V /DescendantFonts [8 0 R] >>", ""))
	b.WriteString(pdfObj(8, "<< /Type /Font /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Adobe) /Ordering (GB1) /Supplement 5 >> >>", ""))
	// A non-Adobe registry is not a registered collection: dropped.
	b.WriteString(pdfObj(9, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [10 0 R] >>", ""))
	b.WriteString(pdfObj(10, "<< /Type /Font /Subtype /CIDFontType0 /CIDSystemInfo << /Registry (Vendor) /Ordering (Japan1) /Supplement 0 >> >>", ""))
	b.WriteString("%%EOF\n")
	entries, err := walkEntries(t, "t.pdf", []byte(b.String()), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	page, _, _ := strings.Cut(entries["t.pdf#text"], "Adobe") // dictionary strings follow page text
	if got := strings.Join(strings.Fields(page), ""); got != "一中" {
		t.Fatalf("text = %q", entries["t.pdf#text"])
	}
}
