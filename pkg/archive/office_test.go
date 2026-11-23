package archive

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

func biffRec(typ uint16, body []byte) []byte {
	return append(append(le16(typ), le16(uint16(len(body)))...), body...)
}

// buildWordDoc writes a FIB whose piece table (in 1Table) holds one
// compressed cp1252 piece and one UTF-16 piece. flags is OR-ed into the FIB.
func buildWordDoc(t *testing.T, flags uint16, ccps ...uint32) []byte {
	t.Helper()
	word := make([]byte, 0x600)
	for i, c := range ccps { // ccpText, ccpFtn, ccpHdd, reserved, ccpAtn, ...
		binary.LittleEndian.PutUint32(word[wordFibCcpText+4*i:], c)
	}
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
	if _, ok := entries["a.doc!1Table"]; ok {
		t.Fatal("the table stream consumed by text extraction must not be scanned raw")
	}
}

func TestWalkWordStoriesAreSeparated(t *testing.T) {
	// 16 main-text CPs, then 24 header CPs.
	entries, err := walkEntries(t, "s.doc", buildWordDoc(t, 0, 16, 0, 24), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := entries["s.doc!WordDocument#text"]; got != "FIXTURE-WORD-“q”\n" {
		t.Fatalf("main text = %q", got)
	}
	if got := entries["s.doc!WordDocument#headers"]; got != "SPLITfield\nnext line\n" {
		t.Fatalf("headers = %q (entries %q)", got, entries)
	}
}

func TestWalkOle10NativeObjectPool(t *testing.T) {
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("inner.txt")
	w.Write([]byte("FIXTURE-OLE-NATIVE-ZIP"))
	zw.Close()
	payload := zbuf.Bytes()
	var native bytes.Buffer
	native.Write(le32(0)) // total size, patched below
	native.Write(le16(2))
	native.WriteString("secret.zip\x00")
	native.WriteString(`C:\Users\someone\secret.zip` + "\x00")
	native.Write(le32(0x00030000))
	native.Write(le32(0))
	native.WriteString(`C:\Temp\secret.zip` + "\x00")
	native.Write(le32(uint32(len(payload))))
	native.Write(payload)
	nb := native.Bytes()
	binary.LittleEndian.PutUint32(nb, uint32(len(nb)-4))
	data := buildCFB(t, 1, []cfbEntry{
		{name: "ObjectPool", typ: 1, child: 2, right: -1},
		{name: "_1234", typ: 1, child: 3, right: -1},
		{name: "\x01Ole10Native", typ: 2, data: nb, child: -1, right: 4},
		{name: "\x01CompObj", typ: 2, data: []byte("FIXTURE-COMPOBJ-NOISE"), child: -1, right: -1},
	})
	entries, err := walkEntries(t, "o.doc", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	found := false
	for p, v := range entries {
		if strings.HasSuffix(p, "Ole10Native!secret.zip!inner.txt") && v == "FIXTURE-OLE-NATIVE-ZIP" {
			found = true
		}
		if strings.Contains(v, "COMPOBJ") || strings.Contains(v, `C:\Temp`) {
			t.Fatalf("metadata scanned: %q", p)
		}
	}
	if !found {
		t.Fatalf("embedded zip not recursed: %q", entries)
	}
	// A malformed header falls back to the raw stream.
	data = buildCFB(t, 1, []cfbEntry{{name: "\x01Ole10Native", typ: 2, data: []byte("FIXTURE-BAD-NATIVE"), child: -1, right: -1}})
	entries, err = walkEntries(t, "b.doc", data, Limits{})
	if !partialKinds(err)["corrupt-entry"] {
		t.Fatalf("want corrupt-entry, got %v", err)
	}
	for p, v := range entries {
		if strings.Contains(v, "FIXTURE-BAD-NATIVE") {
			return
		}
		_ = p
	}
	t.Fatalf("raw fallback missing: %q", entries)
}

// buildPropertySet writes a one-section property set: codepage, an ANSI
// title, a UTF-16 string, a string vector, and a user-property dictionary.
func buildPropertySet(codepage uint16) []byte {
	type prop struct {
		id  uint32
		val []byte
	}
	pad := func(b []byte) []byte { return append(b, make([]byte, (4-len(b)%4)%4)...) }
	lpstr := func(s string) []byte { return pad(append(le32(uint32(len(s)+1)), append([]byte(s), 0)...)) }
	props := []prop{
		{1, append(le32(vtI2), le16(codepage)...)},
		{2, append(le32(vtLPSTR), lpstr("FIXTURE-TITLE-\x93q\x94")...)},
		{3, append(le32(vtLPWSTR), pad(append(le32(6), utf16le("PROP-W\x00")[:12]...))...)},
		{13, append(append(le32(vtVector|vtLPSTR), le32(2)...), append(lpstr("Sheet1"), lpstr("FIXTURE-PART")...)...)},
		{0, append(le32(1), append(le32(5), lpstr("FIXTURE-CUSTOM-NAME")...)...)},
	}
	head := 8 + 8*len(props)
	var body, index []byte
	for _, p := range props {
		index = append(index, le32(p.id)...)
		index = append(index, le32(uint32(head+len(body)))...)
		body = append(body, pad(p.val)...)
	}
	sec := append(append(le32(uint32(head+len(body))), le32(uint32(len(props)))...), append(index, body...)...)
	b := append(le16(0xFFFE), le16(0)...)
	b = append(b, le32(0x00020006)...)
	b = append(b, make([]byte, 16)...)
	b = append(b, le32(1)...)
	b = append(b, make([]byte, 16)...) // FMTID
	b = append(b, le32(48)...)
	return append(b, sec...)
}

func TestWalkSummaryInformationText(t *testing.T) {
	data := buildCFB(t, 1, []cfbEntry{{name: "\x05SummaryInformation", typ: 2, data: buildPropertySet(1252), child: -1, right: -1}})
	entries, err := walkEntries(t, "p.doc", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	var text string
	for p, v := range entries {
		if strings.HasSuffix(p, "SummaryInformation#text") {
			text = v
		} else {
			t.Fatalf("raw property stream emitted: %q", p)
		}
	}
	for _, want := range []string{"FIXTURE-TITLE-“q”\n", "PROP-W\n", "Sheet1\nFIXTURE-PART\n", "FIXTURE-CUSTOM-NAME\n"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %q", want, text)
		}
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
	f.Add(buildPropertySet(1200), []byte(nil))
	f.Fuzz(func(t *testing.T, stream, table []byte) {
		out := &textBuffer{limit: 1 << 16}
		var marks []wordStoryMark
		_ = extractWordStories(stream, map[string][]byte{"0Table": table, "1Table": table}, out, &marks)
		for i, m := range marks {
			if m.offset > out.buf.Len() || (i > 0 && m.offset < marks[i-1].offset) {
				t.Fatalf("bad story mark %v", marks)
			}
		}
		_ = extractPropertySetText(stream, out)
		_, _, _ = parseOle10Native(stream)
		_ = extractBIFFText(stream, out)
		_ = extractPPTText(stream, out)
		if int64(out.buf.Len()) > out.limit {
			t.Fatal("extractor exceeded limit")
		}
	})
}
