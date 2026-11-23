package archive

import (
	"bytes"
	"compress/bzip2"
	"compress/flate"
	"encoding/binary"
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/ulikunitz/xz/lzma"
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
	case eggMethodLZMA:
		return eggLZMABlock(t, plain)
	}
	return plain
}

// eggLZMABlock lays out an LZMA block the way ALZip writes it (observed in
// real ALZip output): LZMA SDK version 0x4104 and properties size 5, the
// properties (lc=3 lp=0 pb=2, dictionary size), then the raw LZMA stream.
func eggLZMABlock(t testing.TB, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := lzma.WriterConfig{DictCap: 1 << 16, Size: int64(len(plain)), SizeInHeader: true}.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(plain)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	classic := buf.Bytes() // props(1) dict(4) size(8) stream
	return append(append([]byte{0x04, 0x41, 0x05, 0x00}, classic[:5]...), classic[13:]...)
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
		{name: "unknown.bin", blocks: []eggTestBlock{{method: 9, plain: []byte("xx"), comp: []byte("yy")}}},
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

func TestWalkEggLZMA(t *testing.T) {
	plain := bytes.Repeat([]byte("FIXTURE-EGG-LZMA "), 200)
	data := buildEgg(t, nil, []eggTestFile{
		{name: "one.txt", blocks: []eggTestBlock{{method: eggMethodLZMA, plain: plain}}},
		{name: "two.txt", blocks: []eggTestBlock{
			{method: eggMethodLZMA, plain: []byte("FIXTURE-EGG-")},
			{method: eggMethodLZMA, plain: []byte("LZMA-MULTI\n")},
		}},
	})
	entries, err := walkEntries(t, "l.egg", data, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if got := entries["l.egg!one.txt"]; !bytes.Equal([]byte(got), plain) {
		t.Fatalf("one.txt: got %d bytes", len(got))
	}
	requireEntry(t, entries, "l.egg!two.txt", "FIXTURE-EGG-LZMA-MULTI")
}

func TestWalkEggLZMARejectsHugeDictionary(t *testing.T) {
	comp := eggLZMABlock(t, []byte("x"))
	binary.LittleEndian.PutUint32(comp[5:], eggMaxLZMADict+1)
	data := buildEgg(t, nil, []eggTestFile{{name: "d", blocks: []eggTestBlock{{method: eggMethodLZMA, plain: []byte("x"), comp: comp}}}})
	_, err := walkEntries(t, "d.egg", data, Limits{})
	if !partialKinds(err)["unsupported-compression"] {
		t.Fatalf("want unsupported-compression, got %v", err)
	}
}

// eggSpecSolid is the "Solid Archive" example of the EGG Format
// Specification 1.0, section 3, byte for byte: a.txt ("a") and b.txt ("bc")
// share one stored block "abc".
var eggSpecSolid = []byte{
	0x45, 0x47, 0x47, 0x41, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x60, 0xA0, 0xE5, 0x24, 0x00, 0x00, 0x00,
	0x22, 0x82, 0xE2, 0x08,
	0xE3, 0x90, 0x85, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xAC, 0x91, 0x85, 0x0A, 0x00, 0x05, 0x00, 'a', '.', 't', 'x', 't',
	0x0B, 0x95, 0x86, 0x2C, 0x00, 0x09, 0x00, 0x23, 0xC9, 0xA3, 0x4F, 0x63, 0xFB, 0xC7, 0x01, 0x00,
	0x22, 0x82, 0xE2, 0x08,
	0xE3, 0x90, 0x85, 0x0A, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xAC, 0x91, 0x85, 0x0A, 0x00, 0x05, 0x00, 'b', '.', 't', 'x', 't',
	0x0B, 0x95, 0x86, 0x2C, 0x00, 0x09, 0x00, 0x67, 0xFA, 0xA3, 0x4F, 0x63, 0xFB, 0xC7, 0x01, 0x00,
	0x22, 0x82, 0xE2, 0x08,
	0x13, 0x0C, 0xB5, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x6D, 0x48, 0x83, 0x9E,
	0x22, 0x82, 0xE2, 0x08,
	'a', 'b', 'c',
	0x22, 0x82, 0xE2, 0x08,
}

func TestWalkEggSolidSpecExample(t *testing.T) {
	entries, err := walkEntries(t, "s.egg", eggSpecSolid, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if entries["s.egg!a.txt"] != "a" || entries["s.egg!b.txt"] != "bc" || len(entries) != 2 {
		t.Fatalf("got %q", entries)
	}
}

// buildSolidEgg writes every file header first and then the archive's blocks,
// as ALZip does for solid compression.
func buildSolidEgg(t *testing.T, names []string, plains [][]byte, extras [][][]byte, blocks []eggTestBlock) []byte {
	t.Helper()
	b := le32(eggHeaderMagic)
	b = append(b, 0, 1)
	b = append(b, le32(1)...)
	b = append(b, le32(0)...)
	b = append(b, eggExtra(eggSolidMagic, 0, nil)...)
	b = append(b, le32(eggEOFARC)...)
	for i, n := range names {
		b = append(b, le32(eggFileMagic)...)
		b = append(b, le32(uint32(i))...)
		b = binary.LittleEndian.AppendUint64(b, uint64(len(plains[i])))
		b = append(b, eggExtra(eggFilenameMagic, 0, []byte(n))...)
		if extras != nil {
			for _, x := range extras[i] {
				b = append(b, x...)
			}
		}
		b = append(b, le32(eggEOFARC)...)
	}
	for _, blk := range blocks {
		comp := blk.comp
		if comp == nil {
			comp = eggCompress(t, blk.method, blk.plain)
		}
		b = append(b, le32(eggBlockMagic)...)
		b = append(b, blk.method, 0)
		b = append(b, le32(uint32(len(blk.plain)))...)
		b = append(b, le32(uint32(len(comp)))...)
		b = append(b, le32(0)...)
		b = append(b, le32(eggEOFARC)...)
		b = append(b, comp...)
	}
	return append(b, le32(eggEOFARC)...)
}

func TestWalkEggSolidMultiBlock(t *testing.T) {
	names := []string{"dir", "first.txt", "skip/../../evil", "third.txt"}
	plains := [][]byte{nil, []byte("FIXTURE-SOLID-ONE\n"), []byte("dropped"), []byte("FIXTURE-SOLID-THREE\n")}
	stream := bytes.Join(plains, nil)
	dir := [][]byte{eggExtra(eggWindowsMagic, 0, append(make([]byte, 8), eggWinDirectory))}
	for _, method := range []byte{eggMethodDeflate, eggMethodLZMA} {
		// The block boundary falls inside first.txt.
		data := buildSolidEgg(t, names, plains, [][][]byte{dir, nil, nil, nil}, []eggTestBlock{
			{method: method, plain: stream[:7]},
			{method: method, plain: stream[7:]},
		})
		entries, err := walkEntries(t, "s.egg", data, Limits{})
		if !partialKinds(err)["path"] {
			t.Fatalf("method %d: want path gap, got %v", method, err)
		}
		requireEntry(t, entries, "s.egg!first.txt", "FIXTURE-SOLID-ONE")
		requireEntry(t, entries, "s.egg!third.txt", "FIXTURE-SOLID-THREE")
		if len(entries) != 2 {
			t.Fatalf("method %d: got %q", method, entries)
		}
	}
}

func TestWalkEggSolidShortStreamAndBudget(t *testing.T) {
	data := buildSolidEgg(t, []string{"a.txt", "b.txt"}, [][]byte{[]byte("FIXTURE-A"), []byte("FIXTURE-B-LONGER")}, nil,
		[]eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-AFIXTURE-B")}})
	entries, err := walkEntries(t, "s.egg", data, Limits{})
	if !partialKinds(err)["corrupt-entry"] {
		t.Fatalf("want corrupt-entry for a stream shorter than the file lengths, got %v", err)
	}
	requireEntry(t, entries, "s.egg!a.txt", "FIXTURE-A")
	// A skipped member's bytes are still decoded to realign the stream and
	// count against the expansion budget.
	big := bytes.Repeat([]byte("Z"), 8192)
	enc := eggExtra(eggEncryptMagic, 0, make([]byte, 17))
	binary.LittleEndian.PutUint16(enc[5:], uint16(len(enc)))
	data = buildSolidEgg(t, []string{"enc.bin", "after.txt"}, [][]byte{big, []byte("x")}, [][][]byte{{enc}, nil},
		[]eggTestBlock{{method: eggMethodDeflate, plain: append(append([]byte{}, big...), 'x')}})
	_, err = walkEntries(t, "s.egg", data, Limits{MaxExpandedBytes: 1024})
	if k := partialKinds(err); !k["encrypted"] || !k["max-expanded-bytes"] {
		t.Fatalf("want encrypted and max-expanded-bytes, got %v", err)
	}
}

// splitVolumes cuts a single-volume archive into two ALZip split volumes at
// body offset cut: each volume repeats the EGG header with a split extra
// field (previous and next volume ids) and the second continues the byte
// stream where the first ended.
func splitVolumes(body []byte, cut int) [][]byte {
	vol := func(id, prev, next uint32, rest []byte) []byte {
		v := le32(eggHeaderMagic)
		v = append(v, 0, 1)
		v = append(v, le32(id)...)
		v = append(v, le32(0)...)
		v = append(v, eggExtra(eggSplitMagic, 0, append(le32(prev), le32(next)...))...)
		v = append(v, le32(eggEOFARC)...)
		return append(v, rest...)
	}
	const head = 18 // EGG header (14) and its EOFARC (4)
	return [][]byte{vol(100, 0, 101, body[head:cut]), vol(101, 100, 0, body[cut:])}
}

func TestWalkEggSplitVolumes(t *testing.T) {
	// Incompressible filler keeps the compressed block long enough to cut.
	rng := rand.New(rand.NewPCG(1, 2))
	filler := make([]byte, 4096)
	for i := range filler {
		filler[i] = 'a' + byte(rng.IntN(26))
	}
	plain := []byte("FIXTURE-SPLIT-PREFIX " + string(filler) + " TAIL-IN-SECOND-VOLUME")
	for _, method := range []byte{eggMethodStore, eggMethodDeflate, eggMethodLZMA} {
		body := buildEgg(t, nil, []eggTestFile{
			{name: "whole.txt", blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-WHOLE-MEMBER")}}},
			{name: "cut.txt", blocks: []eggTestBlock{{method: method, plain: plain}}},
		})
		// The first volume ends halfway through cut.txt's block data.
		blk := bytes.Index(body[bytes.Index(body, []byte("cut.txt")):], le32(eggBlockMagic)) + bytes.Index(body, []byte("cut.txt"))
		csize := int(binary.LittleEndian.Uint32(body[blk+10:]))
		cut := blk + 22 + csize/2
		vols := splitVolumes(body, cut)
		entries, err := walkEntries(t, "a.vol1.egg", vols[0], Limits{})
		if !partialKinds(err)["split-volume"] {
			t.Fatalf("method %d: want split-volume gap, got %v", method, err)
		}
		requireEntry(t, entries, "a.vol1.egg!whole.txt", "FIXTURE-WHOLE-MEMBER")
		requireEntry(t, entries, "a.vol1.egg!cut.txt", "FIXTURE-SPLIT-PREFIX")
		if got := entries["a.vol1.egg!cut.txt"]; strings.Contains(got, "TAIL") {
			t.Fatalf("method %d: prefix must stop at the cut, got %q", method, got)
		}
		entries, err = walkEntries(t, "a.vol2.egg", vols[1], Limits{})
		if !partialKinds(err)["split-volume"] {
			t.Fatalf("method %d: want split-volume gap for continuation, got %v", method, err)
		}
		if _, ok := entries["a.vol2.egg"]; !ok {
			t.Fatalf("method %d: continuation volume must be scanned raw, got %q", method, entries)
		}
	}
}

func TestWalkEggSkipsDummyHeaders(t *testing.T) {
	body := buildEgg(t, nil, []eggTestFile{{name: "d.txt",
		extras: [][]byte{eggExtra(eggDummyMagic, 0, make([]byte, 8))},
		blocks: []eggTestBlock{{method: eggMethodStore, plain: []byte("FIXTURE-DUMMY")}}}})
	// A top-level dummy header between members.
	i := bytes.LastIndex(body, le32(eggCommentMagic))
	body = append(append(append([]byte{}, body[:i]...), eggExtra(eggDummyMagic, 0, make([]byte, 8))...), body[i:]...)
	entries, err := walkEntries(t, "d.egg", body, Limits{})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	requireEntry(t, entries, "d.egg!d.txt", "FIXTURE-DUMMY")
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
	f.Add(eggSpecSolid)
	f.Add(buildEgg(&testing.T{}, nil, []eggTestFile{{name: "l", blocks: []eggTestBlock{{method: eggMethodLZMA, plain: []byte("hello lzma")}}}}))
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
