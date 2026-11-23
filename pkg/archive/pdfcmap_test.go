package archive

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"strings"
	"testing"
)

// testdata/tounicode.pdf is Chrome print-to-PDF output (Skia): subset fonts
// with Identity-H encoding, per-glyph Td positioning, and ToUnicode CMaps.
// The token never appears in the file as plain bytes.
func TestExtractPDFToUnicodeRealWorld(t *testing.T) {
	data, err := os.ReadFile("testdata/tounicode.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("FIXTURE-CMAP")) {
		t.Fatal("fixture must not contain the token as plain bytes")
	}
	entries, err := walkEntries(t, "c.pdf", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "c.pdf#text", "token FIXTURE-CMAP-TOKEN", "Hello PDF world", "\n日本語テキスト\n")
	if strings.Contains(entries["c.pdf#text"], "Adobe") {
		t.Error("CMap program text leaked into extracted text")
	}
}

func pdfFlateStream(t *testing.T, num int, extra, content string) string {
	t.Helper()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(content))
	zw.Close()
	return fmt.Sprintf("%d 0 obj\n<< /Length %d /Filter /FlateDecode %s >>\nstream\n%s\nendstream\nendobj\n", num, z.Len(), extra, z.String())
}

func TestExtractPDFToUnicodeObjStmAndRanges(t *testing.T) {
	cmap := `/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar <0001> <0046> <0002> <0049> endbfchar
2 beginbfrange <0010> <0019> <0030> <0020> <0022> [<0058> <0054> <0055>] endbfrange
endcmap CMapName currentdict /CMap defineresource pop end end`
	// "FIX" "TU" (bfchar/array) then digits 0..9 via the dst-string range,
	// split across two content streams referenced through an indirect array.
	c1 := "BT /F1 9 Tf 10 700 Td <000100020020> Tj 5 0 Td <00210022> Tj ET"
	c2 := "BT /F1 9 Tf 10 680 Td [<0010>-30<0011><0019>] TJ /F2 9 Tf (plain) Tj ET"
	// The page (3) and its font dict (5) live in the object stream.
	page := "<< /Type /Page /Resources << /Font << /F1 5 0 R /F2 9 0 R >> >> /Contents 4 0 R >>"
	font := "<< /Type /Font /Subtype /Type0 /Encoding /Identity-H /ToUnicode 6 0 R >>"
	objStm := fmt.Sprintf("3 0 5 %d ", len(page)+1)
	stm := objStm + page + " " + font
	var b strings.Builder
	b.WriteString("%PDF-1.7\n")
	b.WriteString(pdfFlateStream(t, 2, fmt.Sprintf("/Type /ObjStm /N 2 /First %d", len(objStm)), stm))
	b.WriteString("4 0 obj\n[7 0 R 8 0 R]\nendobj\n")
	b.WriteString(pdfFlateStream(t, 6, "", cmap))
	b.WriteString(pdfFlateStream(t, 7, "", c1))
	b.WriteString(pdfFlateStream(t, 8, "", c2))
	b.WriteString("9 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n%%EOF\n")
	entries, err := walkEntries(t, "o.pdf", []byte(b.String()), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "o.pdf#text", "FIXTU\n", "019plain")
}

func TestParseCMapIgnoresHostileRanges(t *testing.T) {
	cm := parseCMap([]byte("1 beginbfrange <0000> <FFFF> <0041> endbfrange 1 beginbfrange <0000> <FFFFFFFF> <0041> endbfrange 1 beginbfrange <05> <01> <0041> endbfrange"))
	if cm == nil {
		t.Fatal("want cmap")
	}
	if got := string(cm.decode([]byte{0, 0, 0, 1})); got != "AB" {
		t.Fatalf("decode = %q", got)
	}
	if parseCMap([]byte("garbage <00")) != nil {
		t.Fatal("want nil for cmap without mappings")
	}
}
