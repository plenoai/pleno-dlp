package archive

import (
	"bytes"
	"compress/flate"
	"embed"
	"encoding/binary"
	"io"
	"regexp"
	"sync"
	"unicode/utf8"
)

// Registered CID character collections. A CID font whose CIDSystemInfo
// names Registry (Adobe) and one of these orderings numbers its glyphs by
// the collection's CIDs, so with Identity-H/V encoding a 2-byte code is a
// CID whose Unicode value the collection defines even when the file has no
// /ToUnicode CMap (macOS Quartz CJK output). The tables in cidmaps/ are
// generated from Adobe's cmap-resources (BSD-3-Clause, cidmaps/LICENSE.md)
// by scripts/gencidmap at a pinned upstream commit; each ordering is
// inflated on first use only.

//go:generate go run ../../scripts/gencidmap -out cidmaps

//go:embed cidmaps/*.bin
var cidMapFS embed.FS

var (
	cidMapMu     sync.Mutex
	cidMapTables = map[string]map[uint16]rune{}

	pdfCIDSystemInfo = regexp.MustCompile(`/CIDSystemInfo\s*`)
	pdfRegistryRe    = regexp.MustCompile(`/Registry\s*\(([^)]*)\)`)
	pdfOrderingRe    = regexp.MustCompile(`/Ordering\s*\(([^)]*)\)`)
)

// cidOrderingTable returns CID -> code point for a registered Adobe
// ordering, or nil when the ordering has no embedded table.
func cidOrderingTable(ordering string) map[uint16]rune {
	cidMapMu.Lock()
	defer cidMapMu.Unlock()
	if t, ok := cidMapTables[ordering]; ok {
		return t
	}
	t := loadCIDTable(ordering)
	cidMapTables[ordering] = t
	return t
}

func loadCIDTable(ordering string) map[uint16]rune {
	switch ordering {
	case "Japan1", "GB1", "CNS1", "Korea1", "KR":
	default:
		return nil
	}
	z, err := cidMapFS.ReadFile("cidmaps/" + ordering + ".bin")
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(flate.NewReader(bytes.NewReader(z)))
	if err != nil {
		return nil
	}
	t := map[uint16]rune{}
	next := uint64(0)
	for len(raw) > 0 {
		delta, n1 := binary.Uvarint(raw)
		if n1 <= 0 {
			return nil
		}
		cp, n2 := binary.Uvarint(raw[n1:])
		if n2 <= 0 {
			return nil
		}
		run, n3 := binary.Uvarint(raw[n1+n2:])
		if n3 <= 0 {
			return nil
		}
		raw = raw[n1+n2+n3:]
		cid := next + delta
		if cid+run > 1<<16 || cp+run > utf8.MaxRune {
			return nil
		}
		for i := range run {
			t[uint16(cid+i)] = rune(cp + i)
		}
		next = cid + run
	}
	return t
}

// pdfCIDOrderingFont decodes Identity-encoded CIDs through a registered
// ordering's CID -> Unicode table.
type pdfCIDOrderingFont struct {
	table map[uint16]rune
}

func (f *pdfCIDOrderingFont) decode(b []byte) []byte {
	var out []byte
	for i := 0; i+1 < len(b); i += 2 {
		if r, ok := f.table[binary.BigEndian.Uint16(b[i:])]; ok {
			out = utf8.AppendRune(out, r)
		}
	}
	return out
}

// pdfType0Ordering builds a decoder for an Identity-encoded Type0 font
// whose descendant declares a registered Adobe character collection.
func pdfType0Ordering(fontDict []byte, objs map[int]*pdfObject) pdfFont {
	if !bytes.Contains(fontDict, []byte("/Identity-H")) && !bytes.Contains(fontDict, []byte("/Identity-V")) {
		return nil
	}
	desc := pdfDescendantDict(fontDict, objs)
	info := pdfValueAfter(desc, pdfCIDSystemInfo, objs)
	if info == nil {
		return nil
	}
	reg := pdfRegistryRe.FindSubmatch(info)
	ord := pdfOrderingRe.FindSubmatch(info)
	if reg == nil || ord == nil || string(reg[1]) != "Adobe" {
		return nil
	}
	t := cidOrderingTable(string(ord[1]))
	if t == nil {
		return nil
	}
	return &pdfCIDOrderingFont{table: t}
}
