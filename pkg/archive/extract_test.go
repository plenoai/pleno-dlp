package archive

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

func walkEntries(t *testing.T, name string, data []byte, limits Limits) (map[string]string, error) {
	t.Helper()
	if !LooksLikeArchive(data) {
		t.Fatalf("LooksLikeArchive(%s) = false", name)
	}
	entries, err := Walk(name, data, limits)
	out := map[string]string{}
	for _, e := range entries {
		out[e.Path] = string(e.Data)
	}
	return out, err
}

func requireEntry(t *testing.T, entries map[string]string, path string, wants ...string) {
	t.Helper()
	body, ok := entries[path]
	if !ok {
		keys := make([]string, 0, len(entries))
		for k := range entries {
			keys = append(keys, k)
		}
		t.Fatalf("entry %q missing; got %q", path, keys)
	}
	for _, want := range wants {
		if !strings.Contains(body, want) {
			t.Errorf("entry %q missing %q in:\n%s", path, want, body)
		}
	}
}

func TestExtractSQLiteRowsWithColumnNames(t *testing.T) {
	data, err := os.ReadFile("testdata/extract.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := walkEntries(t, "app.db", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want only the derived text entry, got %d", len(entries))
	}
	requireEntry(t, entries, "app.db#text",
		`INSERT INTO "creds" ("id", "name", "api_key", "note") VALUES (1, 'svc', 'FIXTURE-SQLITE-VALUE-0001', X'00');`,
		"-TAIL_FIXTURE_SECRET'", // overflow-page payload
		"value-59-",             // rows on interior-page children
		`INSERT INTO "odd name" ("weird col", "b") VALUES ('it''s here', 42);`)
}

func TestExtractSQLiteCorruptFallsBackToRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/extract.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	data = data[:1500] // truncate mid page 2
	entries, err := walkEntries(t, "cut.db", data, Limits{})
	var partial *PartialError
	if !errors.As(err, &partial) || partial.Kind != "corrupt-entry" {
		t.Fatalf("want corrupt-entry coverage gap, got %v", err)
	}
	if _, ok := entries["cut.db"]; !ok {
		t.Fatalf("raw fallback missing: %v", entries)
	}
}

func TestExtractPycStringConstants(t *testing.T) {
	data, err := os.ReadFile("testdata/extract.pyc")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := walkEntries(t, "mod.pyc", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "mod.pyc#text", "pyc_FIXTURE_CONSTANT_42", "nested_FIXTURE_STRING", "API_TOKEN")
}

func TestLooksLikePycRejectsText(t *testing.T) {
	for _, s := range []string{"ab\r\nc", "\x00\x00\r\nxxxxxxxxxxxxxxxxxxxxxxx"} {
		if looksLikePyc([]byte(s)) {
			t.Errorf("looksLikePyc(%q) = true", s)
		}
	}
}

func buildPDF(t *testing.T) []byte {
	t.Helper()
	content := "BT /F1 12 Tf 72 712 Td [(FIXTURE-)-20(PDF-)(TOKEN)] TJ ET\nBT (line\\051two) Tj ET\nBT <FEFF0055006E0069> Tj ET"
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	zw.Write([]byte(content))
	zw.Close()
	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	b.WriteString("1 0 obj\n<< /Author (FIXTURE-INFO-AUTHOR) >>\nendobj\n")
	fmt.Fprintf(&b, "2 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", z.Len())
	b.Write(z.Bytes())
	b.WriteString("\nendstream\nendobj\n")
	b.WriteString("3 0 obj\n<< /Length 10 /Filter /DCTDecode >>\nstream\n\xff\xd8(NOPE)\xff\xd9\nendstream\nendobj\n%%EOF\n")
	return b.Bytes()
}

func TestExtractPDFText(t *testing.T) {
	entries, err := walkEntries(t, "doc.pdf", buildPDF(t), Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "doc.pdf#text", "FIXTURE-PDF-TOKEN", "FIXTURE-INFO-AUTHOR", "line)two", "Uni")
	if strings.Contains(entries["doc.pdf#text"], "NOPE") {
		t.Error("image stream bytes were tokenized as text")
	}
}

func TestExtractOfficeXMLRejoinsSplitRuns(t *testing.T) {
	doc := `<?xml version="1.0"?><w:document><w:body><w:p><w:r><w:t>FIXTURE-</w:t></w:r><w:proofErr/><w:r><w:t xml:space="preserve">DOCX&amp;</w:t></w:r><w:r><w:t>TOKEN</w:t></w:r></w:p><w:p><w:r><w:t>next</w:t></w:r></w:p></w:body></w:document>`
	sheet := `<sst><si><t>FIXTURE-</t></si><si><r><t>XL</t></r><r><t>SX</t></r></si></sst>`
	data := buildZip(t, map[string]string{
		"word/document.xml":    doc,
		"xl/sharedStrings.xml": sheet,
		"word/_rels/x.xml":     "<r/>",
		"other.xml":            "<a>b</a>",
	})
	entries, err := walkEntries(t, "f.docx", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "f.docx!word/document.xml#text", "FIXTURE-DOCX&TOKEN\nnext")
	requireEntry(t, entries, "f.docx!xl/sharedStrings.xml#text", "XLSX")
	requireEntry(t, entries, "f.docx!word/document.xml", "<w:t>FIXTURE-</w:t>")
	for _, absent := range []string{"f.docx!word/_rels/x.xml#text", "f.docx!other.xml#text"} {
		if _, ok := entries[absent]; ok {
			t.Errorf("unexpected derived entry %s", absent)
		}
	}
}

func buildAsar(t *testing.T, files map[string][]byte, extra map[string]any) []byte {
	t.Helper()
	root := map[string]any{}
	var payload bytes.Buffer
	for name, body := range files {
		node := root
		parts := strings.Split(name, "/")
		for _, dir := range parts[:len(parts)-1] {
			child, ok := node[dir].(map[string]any)
			if !ok {
				child = map[string]any{"files": map[string]any{}}
				node[dir] = child
			}
			node = child["files"].(map[string]any)
		}
		node[parts[len(parts)-1]] = map[string]any{"offset": fmt.Sprint(payload.Len()), "size": len(body)}
		payload.Write(body)
	}
	for k, v := range extra {
		root[k] = v
	}
	header, err := json.Marshal(map[string]any{"files": root})
	if err != nil {
		t.Fatal(err)
	}
	padded := (len(header) + 3) &^ 3
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, []uint32{4, uint32(padded + 8), uint32(padded + 4), uint32(len(header))})
	b.Write(header)
	b.Write(make([]byte, padded-len(header)))
	b.Write(payload.Bytes())
	return b.Bytes()
}

func TestWalkAsarMembersAndNesting(t *testing.T) {
	inner := buildZip(t, map[string]string{"deep.txt": "FIXTURE-ASAR-ZIP"})
	data := buildAsar(t, map[string][]byte{
		"package.json":     []byte(`{"name":"x"}`),
		"lib/config/a.env": []byte("TOKEN=FIXTURE-ASAR-ENV"),
		"lib/bundle.zip":   inner,
	}, map[string]any{
		"native.node": map[string]any{"size": 3, "unpacked": true},
		"evil":        map[string]any{"offset": "999999", "size": 5},
	})
	entries, err := walkEntries(t, "app.asar", data, Limits{})
	requireEntry(t, entries, "app.asar!package.json", `"name"`)
	requireEntry(t, entries, "app.asar!lib/config/a.env", "FIXTURE-ASAR-ENV")
	requireEntry(t, entries, "app.asar!lib/bundle.zip!deep.txt", "FIXTURE-ASAR-ZIP")
	kinds := partialKinds(err)
	if !kinds["asar-unpacked"] || !kinds["corrupt-entry"] {
		t.Fatalf("want asar-unpacked and corrupt-entry gaps, got %v", err)
	}
}

func partialKinds(err error) map[string]bool {
	kinds := map[string]bool{}
	var walkErrs interface{ Unwrap() []error }
	if errors.As(err, &walkErrs) {
		for _, e := range walkErrs.Unwrap() {
			var p *PartialError
			if errors.As(e, &p) {
				kinds[p.Kind] = true
			}
		}
	}
	var p *PartialError
	if errors.As(err, &p) {
		kinds[p.Kind] = true
	}
	return kinds
}

// cfbEntry describes one directory entry for buildCFB.
type cfbEntry struct {
	name  string
	typ   byte // 1 storage, 2 stream
	data  []byte
	child int32
	right int32
}

// buildCFB writes a minimal v3 compound file. Every stream is padded to the
// 4096-byte mini-stream cutoff so all data lives in regular sectors.
func buildCFB(t *testing.T, rootChild int32, entries []cfbEntry) []byte {
	t.Helper()
	const sector = 512
	const (
		free = 0xffffffff
		eoc  = 0xfffffffe
		fat  = 0xfffffffd
	)
	all := append([]cfbEntry{{name: "Root Entry", typ: 5, child: rootChild, right: -1}}, entries...)
	dirSectors := (len(all)*128 + sector - 1) / sector
	var data bytes.Buffer
	fatTable := []uint32{fat}
	for range dirSectors {
		fatTable = append(fatTable, uint32(len(fatTable)+1))
	}
	fatTable[len(fatTable)-1] = eoc
	starts := make([]uint32, len(all))
	for i, e := range all {
		starts[i] = eoc
		if e.typ != 2 {
			continue
		}
		body := e.data
		if len(body) < 4096 {
			body = append(append([]byte{}, body...), make([]byte, 4096-len(body))...)
		}
		all[i].data = body
		n := (len(body) + sector - 1) / sector
		starts[i] = uint32(len(fatTable))
		for k := range n {
			if k == n-1 {
				fatTable = append(fatTable, eoc)
			} else {
				fatTable = append(fatTable, uint32(len(fatTable)+1))
			}
		}
		padded := make([]byte, n*sector)
		copy(padded, body)
		data.Write(padded)
	}
	if len(fatTable) > sector/4 {
		t.Fatal("test CFB too large")
	}
	for len(fatTable) < sector/4 {
		fatTable = append(fatTable, free)
	}
	var out bytes.Buffer
	header := make([]byte, sector)
	copy(header, oleMagic)
	le := binary.LittleEndian
	le.PutUint16(header[24:], 0x3e)
	le.PutUint16(header[26:], 3)
	le.PutUint16(header[28:], 0xfffe)
	le.PutUint16(header[30:], 9)
	le.PutUint16(header[32:], 6)
	le.PutUint32(header[44:], 1)
	le.PutUint32(header[48:], 1)
	le.PutUint32(header[56:], 4096)
	le.PutUint32(header[60:], eoc)
	le.PutUint32(header[68:], eoc)
	le.PutUint32(header[76:], 0)
	for i := 1; i < 109; i++ {
		le.PutUint32(header[76+4*i:], free)
	}
	out.Write(header)
	binary.Write(&out, le, fatTable)
	dir := make([]byte, dirSectors*sector)
	for i, e := range all {
		d := dir[i*128 : (i+1)*128]
		units := utf16.Encode([]rune(e.name))
		for k, u := range units {
			le.PutUint16(d[2*k:], u)
		}
		le.PutUint16(d[64:], uint16(2*len(units)+2))
		d[66] = e.typ
		d[67] = 1
		le.PutUint32(d[68:], free)
		le.PutUint32(d[72:], uint32(e.right))
		le.PutUint32(d[76:], uint32(e.child))
		le.PutUint32(d[116:], starts[i])
		le.PutUint64(d[120:], uint64(len(all[i].data)))
	}
	// Unused directory slots are empty entries.
	for i := len(all); i < dirSectors*4; i++ {
		d := dir[i*128 : (i+1)*128]
		le.PutUint32(d[68:], free)
		le.PutUint32(d[72:], free)
		le.PutUint32(d[76:], free)
	}
	out.Write(dir)
	out.Write(data.Bytes())
	return out.Bytes()
}

func hwpRecord(tag uint32, body []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, tag|uint32(len(body))<<20)
	b.Write(body)
	return b.Bytes()
}

func utf16le(s string) []byte {
	var b bytes.Buffer
	for _, u := range utf16.Encode([]rune(s)) {
		binary.Write(&b, binary.LittleEndian, u)
	}
	return b.Bytes()
}

func TestWalkHWPSectionText(t *testing.T) {
	var para bytes.Buffer
	para.Write(utf16le("FIXTURE-"))
	// An eight-WCHAR inline control (tab, code 9) between halves of a token
	// in separate records must not leak control payload into the text.
	para.Write(utf16le("HWP"))
	para.Write([]byte{9, 0})
	para.Write(make([]byte, 14))
	para.Write(utf16le("-TEXT\r"))
	records := append(hwpRecord(66, []byte{1, 2, 3, 4}), hwpRecord(hwpTagParaText, para.Bytes())...)
	var deflated bytes.Buffer
	fw, _ := flate.NewWriter(&deflated, flate.BestCompression)
	fw.Write(records)
	fw.Close()
	fileHeader := make([]byte, 256)
	copy(fileHeader, hwpSignature)
	binary.LittleEndian.PutUint32(fileHeader[36:], hwpFlagCompressed)
	data := buildCFB(t, 1, []cfbEntry{
		{name: "FileHeader", typ: 2, data: fileHeader, child: -1, right: 2},
		{name: "BodyText", typ: 1, child: 3, right: -1},
		{name: "Section0", typ: 2, data: deflated.Bytes(), child: -1, right: -1},
	})
	entries, err := walkEntries(t, "doc.hwp", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "doc.hwp!BodyText/Section0#text", "FIXTURE-HWP-TEXT")
	if _, ok := entries["doc.hwp!FileHeader"]; !ok {
		t.Errorf("FileHeader stream not emitted: %v", entries)
	}
}

func TestWalkHWPEncryptedIsCoverageGap(t *testing.T) {
	fileHeader := make([]byte, 256)
	copy(fileHeader, hwpSignature)
	binary.LittleEndian.PutUint32(fileHeader[36:], hwpFlagCompressed|hwpFlagEncrypted)
	data := buildCFB(t, 1, []cfbEntry{{name: "FileHeader", typ: 2, data: fileHeader, child: -1, right: -1}})
	_, err := walkEntries(t, "locked.hwp", data, Limits{})
	if !partialKinds(err)["encrypted"] {
		t.Fatalf("want encrypted gap, got %v", err)
	}
}

func TestWalkGenericOLEStreams(t *testing.T) {
	data := buildCFB(t, 1, []cfbEntry{{name: "WordDocument", typ: 2, data: []byte("FIXTURE-OLE-STREAM"), child: -1, right: -1}})
	entries, err := walkEntries(t, "legacy.doc", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "legacy.doc!WordDocument", "FIXTURE-OLE-STREAM")
}

func TestWalkCorruptOLEIsCoverageGap(t *testing.T) {
	data := append(append([]byte{}, oleMagic...), bytes.Repeat([]byte{0xff}, 600)...)
	_, err := walkEntries(t, "bad.doc", data, Limits{})
	if !partialKinds(err)["corrupt-archive"] {
		t.Fatalf("want corrupt-archive gap, got %v", err)
	}
}

func TestEggIsScannedRaw(t *testing.T) {
	data := append([]byte("EGGA\x00\x01"), []byte(" stored FIXTURE-EGG ")...)
	entries, err := walkEntries(t, "a.egg", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "a.egg", "FIXTURE-EGG")
}

func TestExtractorOutputHonorsExpansionBudget(t *testing.T) {
	data, err := os.ReadFile("testdata/extract.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	_, err = walkEntries(t, "app.db", data, Limits{MaxExpandedBytes: 512})
	if !partialKinds(err)["max-expanded-bytes"] {
		t.Fatalf("want max-expanded-bytes gap, got %v", err)
	}
}

// FuzzWalkStructured asserts the extractors never panic or exceed budgets on
// hostile input derived from every supported structured format.
func FuzzWalkStructured(f *testing.F) {
	for _, path := range []string{"testdata/extract.sqlite", "testdata/extract.pyc"} {
		if data, err := os.ReadFile(path); err == nil {
			f.Add(data)
		}
	}
	f.Add([]byte("%PDF-1.4\n1 0 obj << /Filter /FlateDecode >> stream\nx\x9c\nendstream (a\\101) <414>"))
	f.Add([]byte("\x04\x00\x00\x00\x20\x00\x00\x00\x1c\x00\x00\x00\x13\x00\x00\x00{\"files\":{\"a\":{}}}"))
	f.Add(append(append([]byte{}, oleMagic...), make([]byte, 1024)...))
	f.Fuzz(func(t *testing.T, data []byte) {
		limits := Limits{MaxExpandedBytes: 1 << 20, MaxEntryBytes: 1 << 20, MaxFiles: 64}
		started := time.Now()
		entries, _ := Walk("fuzz", data, limits)
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Fatalf("Walk took %v on %d bytes", elapsed, len(data))
		}
		var total int
		for _, e := range entries {
			total += len(e.Data)
		}
		if total > 1<<20+len(data) {
			t.Fatalf("emitted %d bytes beyond budget", total)
		}
	})
}
