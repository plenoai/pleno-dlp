package archive

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"encoding/binary"
	"testing"
)

// EGG fixtures are assembled field by field from the ESTsoft layout (see
// egg.go) so each test pins one header or flag.

type eggTestBlock struct {
	method byte
	plain  []byte
	comp   []byte // nil: derived from method
}

type eggTestFile struct {
	name     string
	nameFlag byte
	nameHead []byte // locale / parent id prefix
	extras   [][]byte
	blocks   []eggTestBlock
}

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func eggExtra(magic uint32, flag byte, body []byte) []byte {
	b := le32(magic)
	b = append(b, flag)
	if flag&eggFlagSize4 != 0 {
		b = append(b, le32(uint32(len(body)))...)
	} else {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(body)))
	}
	return append(b, body...)
}

func eggCompress(t *testing.T, method byte, plain []byte) []byte {
	t.Helper()
	switch method {
	case eggMethodDeflate:
		var buf bytes.Buffer
		w, _ := flate.NewWriter(&buf, flate.BestCompression)
		w.Write(plain)
		w.Close()
		return buf.Bytes()
	case eggMethodBzip2:
		// Go has no bzip2 writer; this is `bzip2 -9` of "FIXTURE-EGG-BZIP2\n".
		out := []byte{0x42, 0x5a, 0x68, 0x39, 0x31, 0x41, 0x59, 0x26, 0x53, 0x59, 0xde, 0xf2, 0x7c, 0x0b, 0x00, 0x00, 0x03, 0xde, 0x00, 0x00, 0x10, 0x00, 0x02, 0x10, 0x00, 0x13, 0xa0, 0x56, 0x50, 0x20, 0x00, 0x22, 0x01, 0xa2, 0x68, 0x7a, 0x10, 0x00, 0x01, 0xe8, 0x70, 0x63, 0x50, 0x07, 0x3b, 0xf2, 0x60, 0xe8, 0xbb, 0x92, 0x29, 0xc2, 0x84, 0x86, 0xf7, 0x93, 0xe0, 0x58}
		check, err := readAllBzip2(out)
		if err != nil || !bytes.Equal(check, plain) {
			t.Fatalf("bzip2 fixture mismatch: %q %v", check, err)
		}
		return out
	}
	return plain
}

func readAllBzip2(b []byte) ([]byte, error) {
	var out bytes.Buffer
	_, err := out.ReadFrom(bzip2.NewReader(bytes.NewReader(b)))
	return out.Bytes(), err
}

func buildEgg(t *testing.T, archiveExtras [][]byte, files []eggTestFile) []byte {
	t.Helper()
	b := le32(eggHeaderMagic)
	b = binary.LittleEndian.AppendUint16(b, 0x0100)
	b = append(b, le32(0x1234)...)
	b = append(b, le32(0)...)
	for _, x := range archiveExtras {
		b = append(b, x...)
	}
	b = append(b, le32(eggEOFARC)...)
	for i, f := range files {
		b = append(b, le32(eggFileMagic)...)
		b = append(b, le32(uint32(i))...)
		var total uint64
		for _, blk := range f.blocks {
			total += uint64(len(blk.plain))
		}
		b = binary.LittleEndian.AppendUint64(b, total)
		b = append(b, eggExtra(eggFilenameMagic, f.nameFlag, append(append([]byte{}, f.nameHead...), f.name...))...)
		for _, x := range f.extras {
			b = append(b, x...)
		}
		b = append(b, le32(eggEOFARC)...)
		for _, blk := range f.blocks {
			comp := blk.comp
			if comp == nil {
				comp = eggCompress(t, blk.method, blk.plain)
			}
			b = append(b, le32(eggBlockMagic)...)
			b = append(b, blk.method, 0)
			b = append(b, le32(uint32(len(blk.plain)))...)
			b = append(b, le32(uint32(len(comp)))...)
			b = append(b, le32(0)...) // crc32 (not verified)
			b = append(b, le32(eggEOFARC)...)
			b = append(b, comp...)
		}
	}
	b = append(b, eggExtra(eggCommentMagic, 0, []byte("archive comment"))...)
	return append(b, le32(eggEOFARC)...)
}

func TestWalkEggStoreDeflateBzip2(t *testing.T) {
	data := buildEgg(t, nil, []eggTestFile{
		{name: "dir/stored.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-EGG-STORED\n")}}},
		{name: "deflate.txt", blocks: []eggTestBlock{
			{method: eggMethodDeflate, plain: []byte("FIXTURE-EGG-")},
			{method: eggMethodDeflate, plain: []byte("DEFLATE\n")},
		}},
		{name: "b.txt", nameFlag: eggNameCodepage | eggNameRelative, nameHead: []byte{0xb5, 0x03, 1, 0, 0, 0},
			blocks: []eggTestBlock{{method: eggMethodBzip2, plain: []byte("FIXTURE-EGG-BZIP2\n")}}},
		{name: "folder", extras: [][]byte{eggExtra(eggWindowsMagic, 0, append(make([]byte, 8), eggWinDirectory))}},
	})
	entries, err := walkEntries(t, "a.egg", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "a.egg!dir/stored.txt", "FIXTURE-EGG-STORED")
	requireEntry(t, entries, "a.egg!deflate.txt", "FIXTURE-EGG-DEFLATE")
	requireEntry(t, entries, "a.egg!b.txt", "FIXTURE-EGG-BZIP2")
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %v", entries)
	}
}

func TestWalkEggNestedZip(t *testing.T) {
	inner := buildEgg(t, nil, []eggTestFile{{name: "in.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-NESTED")}}}})
	outer := buildEgg(t, nil, []eggTestFile{{name: "in.egg", blocks: []eggTestBlock{{method: eggMethodDeflate, plain: inner}}}})
	entries, err := walkEntries(t, "o.egg", outer, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "o.egg!in.egg!in.txt", "FIXTURE-NESTED")
}

func TestWalkEggGaps(t *testing.T) {
	encrypt := eggExtra(eggEncryptMagic, 0, append([]byte{0}, make([]byte, 16)...))
	// the encrypt header size counts its own 7 header bytes
	binary.LittleEndian.PutUint16(encrypt[5:], uint16(len(encrypt)))
	data := buildEgg(t, nil, []eggTestFile{
		{name: "enc.txt", extras: [][]byte{encrypt}, blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("SECRET")}}},
		{name: "flag.txt", nameFlag: eggNameEncrypted, blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("SECRET")}}},
		{name: "azo.bin", blocks: []eggTestBlock{{method: eggMethodAZO, plain: []byte("xx"), comp: []byte("yy")}}},
		{name: "lzma.bin", blocks: []eggTestBlock{{method: eggMethodLZMA, plain: []byte("xx"), comp: []byte("yy")}}},
		{name: "ok.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-AFTER-GAPS")}}},
		{name: "../evil", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("x")}}},
	})
	entries, err := walkEntries(t, "a.egg", data, Limits{})
	kinds := partialKinds(err)
	for _, k := range []string{"encrypted", "unsupported-compression", "path"} {
		if !kinds[k] {
			t.Fatalf("want %s gap, got %v", k, err)
		}
	}
	requireEntry(t, entries, "a.egg!ok.txt", "FIXTURE-AFTER-GAPS")
	for p := range entries {
		if p != "a.egg!ok.txt" {
			t.Fatalf("unexpected entry %q", p)
		}
	}
}

func TestWalkEggSolidFallsBackToRaw(t *testing.T) {
	data := buildEgg(t, [][]byte{eggExtra(eggSolidMagic, 0, nil)}, []eggTestFile{
		{name: "s.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-SOLID")}}},
	})
	entries, err := walkEntries(t, "s.egg", data, Limits{})
	if !partialKinds(err)["unsupported-compression"] {
		t.Fatalf("want unsupported-compression gap, got %v", err)
	}
	requireEntry(t, entries, "s.egg", "FIXTURE-SOLID")
}

func TestWalkEggBudgets(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 4096)
	data := buildEgg(t, nil, []eggTestFile{{name: "big", blocks: []eggTestBlock{{method: eggMethodDeflate, plain: big}}}})
	_, err := walkEntries(t, "b.egg", data, Limits{MaxExpandedBytes: 1024})
	if !partialKinds(err)["max-expanded-bytes"] {
		t.Fatalf("want max-expanded-bytes, got %v", err)
	}
	// A lying uncompressed size is a corrupt entry, not silent truncation.
	data = buildEgg(t, nil, []eggTestFile{{name: "lie", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("abcd"), comp: []byte("ab")}}}})
	_, err = walkEntries(t, "l.egg", data, Limits{})
	if !partialKinds(err)["corrupt-entry"] {
		t.Fatalf("want corrupt-entry, got %v", err)
	}
}

func FuzzWalkEgg(f *testing.F) {
	f.Add(buildEgg(&testing.T{}, nil, []eggTestFile{{name: "a", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("hello")}}}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, _ := Walk("f.egg", data, Limits{MaxExpandedBytes: 1 << 20, MaxEntryBytes: 1 << 20, MaxFiles: 64})
		total := 0
		for _, e := range entries {
			total += len(e.Data)
		}
		if total > 1<<20+len(data) {
			t.Fatalf("emitted %d bytes", total)
		}
	})
}
