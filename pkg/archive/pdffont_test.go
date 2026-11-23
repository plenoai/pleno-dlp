package archive

import (
	"bytes"
	"compress/zlib"
	"encoding/ascii85"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"testing"
	"unicode/utf8"
)

// testdata/quartz.pdf is macOS Quartz PDFContext output (cupsfilter of a
// text file): Latin text in a subset TrueType font with /MacRomanEncoding
// and no ToUnicode, Japanese text in a CFF CIDFontType0 (Adobe-Japan1,
// Identity-H) with no ToUnicode.
func TestExtractPDFQuartzRealWorld(t *testing.T) {
	data, err := os.ReadFile("testdata/quartz.pdf")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := walkEntries(t, "q.pdf", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	text := entries["q.pdf#text"]
	requireEntry(t, entries, "q.pdf#text", "quartz token FIXTURE-QUARTZ-TOKEN", "FIXTURE-QUARTZ-CID")
	// Page text (before the document info strings) must hold no CID
	// glyph-index bytes and no embedded font or ICC program bytes.
	page, _, _ := strings.Cut(text, "Adobe Japan1")
	for _, r := range page {
		if (r < 0x20 && r != '\n') || r == utf8.RuneError {
			t.Fatalf("binary bytes leaked into page text: %q", page)
		}
	}
}

func pdfObj(num int, dict, stream string) string {
	if stream == "" && !strings.Contains(dict, "/Length") {
		return fmt.Sprintf("%d 0 obj\n%s\nendobj\n", num, dict)
	}
	return fmt.Sprintf("%d 0 obj\n<< /Length %d %s >>\nstream\n%s\nendstream\nendobj\n", num, len(stream), dict, stream)
}

func zlibBytes(b []byte) string {
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write(b)
	zw.Close()
	return z.String()
}

func TestExtractPDFDifferencesInheritedResourcesAndForms(t *testing.T) {
	// F1: codes 65.. renamed so "ABCDEFGHIJKLM" shows "FIXTURE-DIFFfi" (F.sc → F).
	diff := "<< /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [65 /F /I /X /T /U /R /E /hyphen /D /I /F /F.sc /fi] >>"
	// F2 (form only): uniXXXX names and an underscore ligature.
	diff2 := "<< /Differences [33 /uni0046 /uni0049 /uni0058 /u0054 /U_R /E /hyphen /F /O /R /M] >>"
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	b.WriteString(pdfObj(1, "<< /Type /Pages /Kids [3 0 R] /Count 1 /Resources << /Font << /F1 5 0 R >> /XObject << /Fm1 7 0 R /Img 9 0 R >> >> >>", ""))
	// The page has no /Resources of its own: they come from the Pages node.
	b.WriteString(pdfObj(3, "<< /Type /Page /Parent 1 0 R /Contents 4 0 R >>", ""))
	b.WriteString(pdfObj(4, "", "BT /F1 9 Tf 10 700 Td (ABCDEFGHIJKLM) Tj ET /Fm1 Do /Img Do"))
	b.WriteString(pdfObj(5, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding 6 0 R >>", ""))
	b.WriteString(pdfObj(6, diff, ""))
	// The form uses its own resources and invokes itself (cycle) and a
	// nested form that inherits the invoking resources.
	b.WriteString(pdfObj(7, "/Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /Font << /F2 8 0 R >> /XObject << /Self 7 0 R /Inner 10 0 R >> >>",
		"BT /F2 9 Tf 10 600 Td (!\"#$%&'()*+) Tj ET /Self Do /Inner Do"))
	b.WriteString(pdfObj(8, "<< /Type /Font /Subtype /Type1 /Encoding "+diff2+" >>", ""))
	b.WriteString(pdfObj(9, "/Type /XObject /Subtype /Image /Width 1 /Height 1", "\x00"))
	b.WriteString(pdfObj(10, "/Type /XObject /Subtype /Form", "BT /F2 9 Tf 10 500 Td (%&) Tj ET"))
	b.WriteString("%%EOF\n")
	data := []byte(b.String())
	entries, err := walkEntries(t, "d.pdf", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	text := entries["d.pdf#text"]
	requireEntry(t, entries, "d.pdf#text", "FIXTURE-DIFFfi\n", "FIXTURE-FORM\n", "\nURE\n")
	if strings.Count(text, "FIXTURE-FORM") != 1 {
		t.Fatalf("form rendered more than once: %q", text)
	}
	if strings.Contains(text, "ABCDEFG") {
		t.Fatalf("raw codes emitted beside decoded text: %q", text)
	}
}

// sfntWithCmap builds a TrueType program holding only a (3,1) format 4 cmap
// that maps 'A'..'Z' to glyph ids 1..26.
func sfntWithCmap() []byte {
	sub := []uint16{4, 0, 0, 4, 4, 1, 0, // format, length, language, segX2, searchRange, entrySelector, rangeShift
		0x5A, 0xFFFF, 0, // endCode, reservedPad
		0x41, 0xFFFF, // startCode
		uint16(1 - 0x41 + 0x10000), 1, // idDelta
		0, 0} // idRangeOffset
	sub[1] = uint16(2 * len(sub))
	var cmap []byte
	cmap = binary.BigEndian.AppendUint16(cmap, 0)
	cmap = binary.BigEndian.AppendUint16(cmap, 1)
	cmap = binary.BigEndian.AppendUint16(cmap, 3)
	cmap = binary.BigEndian.AppendUint16(cmap, 1)
	cmap = binary.BigEndian.AppendUint32(cmap, 12)
	for _, v := range sub {
		cmap = binary.BigEndian.AppendUint16(cmap, v)
	}
	font := []byte{0, 1, 0, 0, 0, 1, 0, 16, 0, 0, 0, 0}
	font = append(font, "cmap"...)
	font = binary.BigEndian.AppendUint32(font, 0)
	font = binary.BigEndian.AppendUint32(font, 28)
	font = binary.BigEndian.AppendUint32(font, uint32(len(cmap)))
	return append(font, cmap...)
}

func TestExtractPDFType0TrueTypeWithoutToUnicode(t *testing.T) {
	// gid = letter - 0x40: F=6 I=9 X=24 T=20 U=21 R=18 E=5 G=7 L=12 Y=25 P=16 H=8
	var codes []byte
	for _, c := range "FIXTUREGLYPH" {
		codes = binary.BigEndian.AppendUint16(codes, uint16(c-0x40))
	}
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	b.WriteString(pdfObj(3, "<< /Type /Page /Resources << /Font << /F1 5 0 R /F9 9 0 R >> >> /Contents 4 0 R >>", ""))
	b.WriteString(pdfObj(4, "", fmt.Sprintf("BT /F1 9 Tf 10 700 Td <%X> Tj ET BT /F9 9 Tf 10 600 Td <0102> Tj ET", codes)))
	b.WriteString(pdfObj(5, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [6 0 R] >>", ""))
	b.WriteString(pdfObj(6, "<< /Type /Font /Subtype /CIDFontType2 /FontDescriptor 7 0 R /CIDToGIDMap /Identity >>", ""))
	b.WriteString(pdfObj(7, "<< /Type /FontDescriptor /FontFile2 8 0 R >>", ""))
	b.WriteString(pdfObj(8, "/Filter /FlateDecode", zlibBytes(sfntWithCmap())))
	// A CFF CID font without ToUnicode: its glyph indices are dropped.
	b.WriteString(pdfObj(9, "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /DescendantFonts [10 0 R] >>", ""))
	b.WriteString(pdfObj(10, "<< /Type /Font /Subtype /CIDFontType0 >>", ""))
	b.WriteString("%%EOF\n")
	entries, err := walkEntries(t, "t.pdf", []byte(b.String()), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := entries["t.pdf#text"]; got != "FIXTUREGLYPH\n" {
		t.Fatalf("text = %q", got)
	}
}

func TestExtractPDFStreamFilters(t *testing.T) {
	content := "BT /F1 9 Tf 10 700 Td (FIXTURE-A85-FLATE) Tj ET"
	var a85 bytes.Buffer
	w := ascii85.NewEncoder(&a85)
	w.Write([]byte(zlibBytes([]byte(content))))
	w.Close()
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	b.WriteString(pdfObj(4, "/Filter [/ASCII85Decode /FlateDecode]", a85.String()+"~>"))
	b.WriteString(pdfObj(5, "/Filter /ASCIIHexDecode", fmt.Sprintf("%X>", "(FIXTURE-AHX) Tj")))
	b.WriteString(pdfObj(6, "/Filter /RunLengthDecode", "\x10(FIXTURE-RLE-AA)\xfeZ\x05 Tj ET\x80"))
	b.WriteString(pdfObj(7, "/Filter /LZWDecode", "\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01"))
	b.WriteString(pdfObj(8, "/Filter /DCTDecode", "(FIXTURE-SHOULD-NOT-APPEAR) Tj"))
	b.WriteString("%%EOF\n")
	entries, err := walkEntries(t, "f.pdf", []byte(b.String()), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "f.pdf#text", "FIXTURE-A85-FLATE", "FIXTURE-AHX", "FIXTURE-RLE-AA")
	if strings.Contains(entries["f.pdf#text"], "SHOULD-NOT-APPEAR") {
		t.Fatal("image-filter stream decoded as text")
	}
}

func TestPDFFilterPrimitives(t *testing.T) {
	// PDF 32000-1 §7.4.4.2 example: "-----A---B" (EarlyChange 1).
	got, err := pdfLZW([]byte{0x80, 0x0B, 0x60, 0x50, 0x22, 0x0C, 0x0C, 0x85, 0x01}, true)
	if err != nil || string(got) != "-----A---B" {
		t.Fatalf("LZW = %q %v", got, err)
	}
	if got, _ := pdfRunLength([]byte{2, 'a', 'b', 'c', 0xFF, 'z', 0x80, 'x'}); string(got) != "abczz" {
		t.Fatalf("RunLength = %q", got)
	}
	if got, err := pdfASCII85([]byte("<~87cURD]i,\"Ebo80~>")); err != nil || string(got) != "Hello World!" {
		t.Fatalf("ASCII85 = %q %v", got, err)
	}
	if got := pdfASCIIHex([]byte("48 65 6C6C 6F7>")); string(got) != "Hellop" {
		t.Fatalf("ASCIIHex = %q", got)
	}
	// PNG Up predictor, 3 columns: rows "abc" then "abc"+1 each.
	rows := []byte{2, 'a', 'b', 'c', 2, 1, 1, 1}
	if got, err := pdfPredict(rows, []byte("<< /Predictor 12 /Columns 3 >>")); err != nil || string(got) != "abcbcd" {
		t.Fatalf("PNG Up = %q %v", got, err)
	}
	// Sub, Average, Paeth on one row each.
	for _, tc := range []struct {
		row  []byte
		want string
	}{
		{[]byte{1, 'a', 1, 1}, "abc"},
		{[]byte{0, 'a', 'b', 'c', 3, 'a' - 'a'/2, 'b' - ('a'+'b')/2, 'c' - ('b'+'c')/2}, "abcabc"},
		{[]byte{0, 'a', 'b', 'c', 4, 0, 0, 0}, "abcabc"},
	} {
		if got, err := pdfPredict(tc.row, []byte("/Predictor 15 /Columns 3")); err != nil || string(got) != tc.want {
			t.Fatalf("predictor %v = %q %v", tc.row, got, err)
		}
	}
	if got, _ := pdfPredict([]byte{'a', 1, 1}, []byte("/Predictor 2 /Columns 3")); string(got) != "abc" {
		t.Fatalf("TIFF = %q", got)
	}
	if _, err := pdfPredict([]byte{0}, []byte("/Predictor 12 /Columns 9999999")); err == nil {
		t.Fatal("want parameter error")
	}
}

func TestGlyphNameToUnicode(t *testing.T) {
	for name, want := range map[string]string{
		"A": "A", "quotesingle": "'", "Euro": "€", "fi": "fi", "f_f_i": "ffi", "a.sc": "a",
		"uni20AC": "€", "uni00410042": "AB", "u1F600": "😀", "uniD800": "", "g123": "", "": "",
	} {
		if got := glyphNameToUnicode(name); got != want {
			t.Errorf("%q = %q, want %q", name, got, want)
		}
	}
}

func FuzzPDFFilters(f *testing.F) {
	f.Add([]byte("\x80\x0b\x60\x50\x22\x0c\x0c\x85\x01"), []byte("/Predictor 12 /Columns 3"))
	f.Add([]byte("<~87cURD]i,\"Ebo80~>"), []byte(""))
	f.Fuzz(func(t *testing.T, data, parms []byte) {
		for _, early := range []bool{true, false} {
			if out, _ := pdfLZW(data, early); len(out) > pdfMaxStreamBytes {
				t.Fatal("LZW cap")
			}
		}
		pdfRunLength(data)
		pdfASCII85(data)
		pdfPredict(data, parms)
		trueTypeGlyphUnicode(data)
		pdfFilters(append([]byte("/Filter "), data...))
	})
}
