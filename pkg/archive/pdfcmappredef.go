package archive

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"regexp"
	"strings"
	"sync"
	"unicode/utf16"
	"unicode/utf8"
)

// Predefined CJK CMaps (PDF 32000-1:2008 §9.7.5.2) name a Type0 font's
// byte -> CID encoding without embedding it: legacy code pages such as
// 90ms-RKSJ-H (Shift-JIS), GBK-EUC-H, B5pc-H, KSCms-UHC-H, and Unicode
// encodings such as UniJIS-UCS2-H. Without /ToUnicode:
//   - legacy CMaps decode code -> CID through the tables scripts/gencidmap
//     inverts from the same pinned cid2code.txt (cidmaps/<ordering>-cmaps.bin,
//     column index in pdfcmapnames_gen.go), then CID -> Unicode through the
//     ordering table (pdfcid.go). A -V CMap is its -H table overridden by
//     the vertical-only codes.
//   - Unicode CMaps (Uni*-UCS2/UTF16/UTF8/UTF32) carry the text in the
//     code itself, so the bytes are decoded as UTF-16BE, UTF-8, or UTF-32BE.

var (
	pdfEncodingName  = regexp.MustCompile(`/Encoding\s*/([A-Za-z0-9.+_-]+)`)
	pdfUnicodeCMapRe = regexp.MustCompile(`^Uni[A-Za-z0-9]+-(UCS2|UCS2-HW|UTF8|UTF16|UTF32)-[HV]$`)

	predefMu     sync.Mutex
	predefTables = map[string]*predefCMap{}
)

// predefCMap is one legacy CMap: key (codeLength<<32 | code) -> CID, plus
// the code length implied by each lead byte.
type predefCMap struct {
	cids map[uint64]uint16
	lens [256]uint8
}

// predefCMapColumn maps a CMap name to its cid2code column and direction.
func predefCMapColumn(name string) (column string, vertical bool, ok bool) {
	switch name {
	case "H":
		return "H", false, true
	case "V":
		return "H", true, true
	}
	switch {
	case strings.HasSuffix(name, "-H"):
		column = strings.TrimSuffix(name, "-H")
	case strings.HasSuffix(name, "-V"):
		column, vertical = strings.TrimSuffix(name, "-V"), true
	default:
		// Single-direction CMaps such as Hankaku, Hiragana, Roman.
		column = name
	}
	_, ok = predefinedCMapOrdering[column]
	return column, vertical, ok
}

func loadPredefCMap(name string) *predefCMap {
	predefMu.Lock()
	defer predefMu.Unlock()
	if t, ok := predefTables[name]; ok {
		return t
	}
	t := decodePredefCMap(name)
	predefTables[name] = t
	return t
}

func decodePredefCMap(name string) *predefCMap {
	column, vertical, ok := predefCMapColumn(name)
	if !ok {
		return nil
	}
	z, err := cidMapFS.ReadFile("cidmaps/" + predefinedCMapOrdering[column] + "-cmaps.bin")
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		return nil
	}
	for len(raw) > 0 {
		n, k := binary.Uvarint(raw)
		if k <= 0 || n > uint64(len(raw)-k) {
			return nil
		}
		col := string(raw[k : k+int(n)])
		raw = raw[k+int(n):]
		want := col == column
		var t *predefCMap
		if want {
			t = &predefCMap{cids: map[uint64]uint16{}}
		}
		for dir := range 2 {
			raw, ok = predefRuns(raw, t, want && (dir == 0 || vertical))
			if !ok {
				return nil
			}
		}
		if want {
			return t
		}
	}
	return nil
}

// predefRuns consumes one run list, applying it to t when apply is set.
func predefRuns(raw []byte, t *predefCMap, apply bool) ([]byte, bool) {
	count, k := binary.Uvarint(raw)
	if k <= 0 {
		return nil, false
	}
	raw = raw[k:]
	var nextKey uint64
	var nextCID int64
	for range count {
		dk, k1 := binary.Uvarint(raw)
		if k1 <= 0 {
			return nil, false
		}
		dc, k2 := binary.Varint(raw[k1:])
		if k2 <= 0 {
			return nil, false
		}
		n, k3 := binary.Uvarint(raw[k1+k2:])
		if k3 <= 0 {
			return nil, false
		}
		raw = raw[k1+k2+k3:]
		key := nextKey + dk
		cid := nextCID + dc
		size := key >> 32
		if size < 1 || size > 4 || n > 1<<16 || cid < 0 || cid+int64(n) > 1<<16 || key&0xffffffff+n > 1<<32 {
			return nil, false
		}
		if apply {
			for i := range n {
				k := key + i
				if lead := byte(k >> (8 * (size - 1))); uint8(size) > t.lens[lead] {
					t.lens[lead] = uint8(size)
				}
				t.cids[k] = uint16(cid + int64(i))
			}
		}
		nextKey = key + n
		nextCID = cid + int64(n)
	}
	return raw, true
}

// pdfPredefFont decodes a legacy predefined CMap through its ordering.
type pdfPredefFont struct {
	cmap  *predefCMap
	table map[uint16]rune
}

func (f *pdfPredefFont) decode(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		size := int(f.cmap.lens[b[i]])
		if size == 0 {
			size = 1
		}
		if i+size > len(b) {
			break
		}
		var code uint64
		for _, c := range b[i : i+size] {
			code = code<<8 | uint64(c)
		}
		i += size
		if cid, ok := f.cmap.cids[uint64(size)<<32|code]; ok {
			if r, ok := f.table[cid]; ok {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return out
}

// pdfUnicodeCMapFont decodes a Unicode predefined CMap's codes as text.
type pdfUnicodeCMapFont struct{ form string }

func (f pdfUnicodeCMapFont) decode(b []byte) []byte {
	var out []byte
	switch f.form {
	case "UTF8":
		for len(b) > 0 {
			r, n := utf8.DecodeRune(b)
			if r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
			}
			b = b[n:]
		}
	case "UTF32":
		for ; len(b) >= 4; b = b[4:] {
			if r := rune(binary.BigEndian.Uint32(b)); utf8.ValidRune(r) {
				out = utf8.AppendRune(out, r)
			}
		}
	default: // UCS2, UCS2-HW, UTF16
		units := make([]uint16, 0, len(b)/2)
		for ; len(b) >= 2; b = b[2:] {
			units = append(units, binary.BigEndian.Uint16(b))
		}
		for _, r := range utf16.Decode(units) {
			if r != utf8.RuneError {
				out = utf8.AppendRune(out, r)
			}
		}
	}
	return out
}

// pdfType0Predefined builds a decoder for a Type0 font whose /Encoding
// names a predefined CJK CMap other than Identity; nil otherwise.
func pdfType0Predefined(fontDict []byte) pdfFont {
	m := pdfEncodingName.FindSubmatch(fontDict)
	if m == nil {
		return nil
	}
	name := string(m[1])
	if u := pdfUnicodeCMapRe.FindStringSubmatch(name); u != nil {
		return pdfUnicodeCMapFont{form: strings.TrimSuffix(u[1], "-HW")}
	}
	column, _, ok := predefCMapColumn(name)
	if !ok {
		return nil
	}
	cm := loadPredefCMap(name)
	table := cidOrderingTable(predefinedCMapOrdering[column])
	if cm == nil || table == nil {
		return nil
	}
	return &pdfPredefFont{cmap: cm, table: table}
}
