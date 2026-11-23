package archive

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

func biffRec(typ uint16, body []byte) []byte {
	return append(append(le16(typ), le16(uint16(len(body)))...), body...)
}

// buildWordDoc writes a FIB whose piece table (in 1Table) holds one
// compressed cp1252 piece and one UTF-16 piece. flags is OR-ed into the FIB.
func buildWordDoc(t *testing.T, flags uint16) []byte {
	t.Helper()
	word := make([]byte, 0x600)
	binary.LittleEndian.PutUint16(word, 0xA5EC)
	binary.LittleEndian.PutUint16(word[wordFibFlagsOffset:], wordFibWhichTblStm|flags)
	copy(word[0x400:], "FIXTURE-WORD-\x93q\x94")
	copy(word[0x500:], utf16le("SPLIT\x13field\x15\rnext line\r"))
	var clx bytes.Buffer
	clx.Write([]byte{0x01, 2, 0, 0xAA, 0xBB}) // Prc
	var plc bytes.Buffer
	for _, cp := range []uint32{0, 16, 16 + 24} {
		plc.Write(le32(cp))
	}
	for _, fc := range []uint32{0x400*2 | wordFcCompressed, 0x500} {
		plc.Write(le16(0))
		plc.Write(le32(fc))
		plc.Write(le16(0))
	}
	clx.WriteByte(0x02)
	clx.Write(le32(uint32(plc.Len())))
	clx.Write(plc.Bytes())
	table := append(make([]byte, 16), clx.Bytes()...)
	binary.LittleEndian.PutUint32(word[wordFibFcClx:], 16)
	binary.LittleEndian.PutUint32(word[wordFibLcbClx:], uint32(clx.Len()))
	return buildCFB(t, 1, []cfbEntry{
		{name: "WordDocument", typ: 2, data: word, child: -1, right: 2},
		{name: "1Table", typ: 2, data: table, child: -1, right: -1},
	})
}

func TestWalkWordDocumentText(t *testing.T) {
	entries, err := walkEntries(t, "a.doc", buildWordDoc(t, 0), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "a.doc!WordDocument#text", "FIXTURE-WORD-“q”SPLITfield\nnext line\n")
	if _, ok := entries["a.doc!WordDocument"]; ok {
		t.Fatal("raw WordDocument stream must not be scanned when text extraction succeeds")
	}
	if _, ok := entries["a.doc!1Table"]; !ok {
		t.Fatal("other OLE streams must still be walked")
	}
}

func TestWalkWordEncryptedIsGap(t *testing.T) {
	entries, err := walkEntries(t, "e.doc", buildWordDoc(t, wordFibEncrypted), Limits{})
	if !partialKinds(err)["encrypted"] {
		t.Fatalf("want encrypted gap, got %v", err)
	}
	if _, ok := entries["e.doc!WordDocument"]; ok {
		t.Fatal("encrypted stream must not be emitted")
	}
}

func TestWalkMalformedWordFallsBackToRaw(t *testing.T) {
	data := buildCFB(t, 1, []cfbEntry{{name: "WordDocument", typ: 2, data: []byte("FIXTURE-OLE-STREAM"), child: -1, right: -1}})
	entries, err := walkEntries(t, "m.doc", data, Limits{})
	if !partialKinds(err)["corrupt-entry"] {
		t.Fatalf("want corrupt-entry gap, got %v", err)
	}
	requireEntry(t, entries, "m.doc!WordDocument", "FIXTURE-OLE-STREAM")
}

func TestWalkWorkbookText(t *testing.T) {
	var sst bytes.Buffer
	sst.Write(le32(2))
	sst.Write(le32(2))
	sst.Write(le16(13))
	sst.WriteByte(0) // compressed
	sst.WriteString("FIXTURE-")
	var cont bytes.Buffer
	cont.WriteByte(1) // continued run switches to UTF-16
	cont.Write(utf16le("XLS-A"))
	cont.Write(le16(6))
	cont.WriteByte(0)
	cont.WriteString("second")
	label := append(make([]byte, 6), le16(13)...)
	label = append(label, 0)
	label = append(label, "FIXTURE-LABEL"...)
	stream := biffRec(biffBOF, make([]byte, 16))
	stream = append(stream, biffRec(biffSST, sst.Bytes())...)
	stream = append(stream, biffRec(biffContinue, cont.Bytes())...)
	stream = append(stream, biffRec(biffLabel, label)...)
	data := buildCFB(t, 1, []cfbEntry{{name: "Workbook", typ: 2, data: stream, child: -1, right: -1}})
	entries, err := walkEntries(t, "a.xls", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "a.xls!Workbook#text", "FIXTURE-XLS-A\nsecond\nFIXTURE-LABEL\n")

	enc := append(biffRec(biffBOF, make([]byte, 16)), biffRec(biffFilePass, make([]byte, 6))...)
	data = buildCFB(t, 1, []cfbEntry{{name: "Workbook", typ: 2, data: enc, child: -1, right: -1}})
	if _, err := walkEntries(t, "e.xls", data, Limits{}); !partialKinds(err)["encrypted"] {
		t.Fatalf("want encrypted gap, got %v", err)
	}
}

func TestWalkPowerPointText(t *testing.T) {
	atom := func(typ uint16, body []byte) []byte {
		return append(append(le16(0), le16(typ)...), append(le32(uint32(len(body))), body...)...)
	}
	inner := append(atom(pptTextChars, utf16le("FIXTURE-PPT\rline2")), atom(pptTextBytes, []byte("bytes-text"))...)
	inner = append(inner, atom(0x0FF0, []byte{1, 2, 3})...)
	stream := append(append(le16(0x000F), le16(0x03E8)...), le32(uint32(len(inner)))...)
	stream = append(stream, inner...)
	data := buildCFB(t, 1, []cfbEntry{{name: "PowerPoint Document", typ: 2, data: stream, child: -1, right: -1}})
	entries, err := walkEntries(t, "a.ppt", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "a.ppt!PowerPoint Document#text", "FIXTURE-PPT\nline2\nbytes-text\n")
}

func FuzzOfficeExtractors(f *testing.F) {
	f.Add([]byte{0xEC, 0xA5}, []byte{2, 0, 0, 0, 0})
	f.Add(biffRec(biffBOF, nil), []byte(nil))
	f.Fuzz(func(t *testing.T, stream, table []byte) {
		out := &textBuffer{limit: 1 << 16}
		_ = extractWordText(stream, map[string][]byte{"0Table": table, "1Table": table}, out)
		_ = extractBIFFText(stream, out)
		_ = extractPPTText(stream, out)
		if int64(out.buf.Len()) > out.limit {
			t.Fatal("extractor exceeded limit")
		}
	})
}
