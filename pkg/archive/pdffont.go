package archive

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"
)

// Fonts without a /ToUnicode CMap (PDF 32000-1:2008 §9.10.2):
//   - simple fonts map each byte through /Encoding: a base encoding
//     (WinAnsi, MacRoman, Standard) patched by /Differences glyph names,
//     which resolve through the Adobe Glyph List for New Fonts (aglfn.txt,
//     BSD-3-Clause), uniXXXX/uXXXX names, and common ligatures;
//   - Type0 fonts with an embedded TrueType program (FontFile2) map CIDs to
//     glyph ids (CIDToGIDMap) and invert the program's Unicode cmap.
// CID fonts with only a CFF program and no ToUnicode (macOS Quartz output
// for CJK text, ordering Adobe-Japan1 etc.) carry no Unicode mapping in the
// file; their strings are dropped rather than emitted as glyph-index noise.

type pdfFont interface {
	decode(b []byte) []byte
}

type pdfDropFont struct{}

func (pdfDropFont) decode([]byte) []byte { return nil }

//go:embed aglfn.txt
var aglfnText string

var (
	aglOnce sync.Once
	aglMap  map[string]rune
)

func aglLookup(name string) (string, bool) {
	aglOnce.Do(func() {
		aglMap = make(map[string]rune, 600)
		for _, line := range strings.Split(aglfnText, "\n") {
			if line == "" || line[0] == '#' {
				continue
			}
			f := strings.SplitN(line, ";", 3)
			if len(f) < 2 {
				continue
			}
			if v, err := strconv.ParseUint(f[0], 16, 32); err == nil {
				aglMap[f[1]] = rune(v)
			}
		}
	})
	switch name {
	case "fi", "fl", "ff", "ffi", "ffl":
		return name, true
	}
	if r, ok := aglMap[name]; ok {
		return string(r), true
	}
	return "", false
}

// glyphNameToUnicode resolves a glyph name per the AGL specification:
// suffixes after '.' are dropped, '_' joins ligature components, and
// uniXXXX[XXXX...] / uXXXX[XX] name code points directly.
func glyphNameToUnicode(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	if strings.Contains(name, "_") {
		var b strings.Builder
		for _, part := range strings.Split(name, "_") {
			b.WriteString(glyphNameToUnicode(part))
		}
		return b.String()
	}
	if s, ok := aglLookup(name); ok {
		return s
	}
	if strings.HasPrefix(name, "uni") && len(name) >= 7 && (len(name)-3)%4 == 0 {
		var b strings.Builder
		for i := 3; i < len(name); i += 4 {
			v, err := strconv.ParseUint(name[i:i+4], 16, 16)
			if err != nil || (v >= 0xD800 && v <= 0xDFFF) {
				return ""
			}
			b.WriteRune(rune(v))
		}
		return b.String()
	}
	if strings.HasPrefix(name, "u") && len(name) >= 5 && len(name) <= 7 {
		v, err := strconv.ParseUint(name[1:], 16, 32)
		if err == nil && utf8.ValidRune(rune(v)) {
			return string(rune(v))
		}
	}
	return ""
}

// pdfStandardHigh lists StandardEncoding code points that differ from
// Latin-1 (Annex D.2); unlisted high codes are undefined.
var pdfStandardHigh = map[byte]rune{
	0x27: '’', 0x60: '‘', 0xA1: '¡', 0xA2: '¢', 0xA3: '£', 0xA4: '⁄', 0xA5: '¥', 0xA6: 'ƒ', 0xA7: '§',
	0xA8: '¤', 0xA9: '\'', 0xAA: '“', 0xAB: '«', 0xAC: '‹', 0xAD: '›', 0xAE: 'ﬁ', 0xAF: 'ﬂ',
	0xB1: '–', 0xB2: '†', 0xB3: '‡', 0xB4: '·', 0xB6: '¶', 0xB7: '•', 0xB8: '‚', 0xB9: '„',
	0xBA: '”', 0xBB: '»', 0xBC: '…', 0xBD: '‰', 0xBF: '¿', 0xC1: '`', 0xC2: '´', 0xC3: 'ˆ',
	0xC4: '˜', 0xC5: '¯', 0xC6: '˘', 0xC7: '˙', 0xC8: '¨', 0xCA: '˚', 0xCB: '¸', 0xCD: '˝',
	0xCE: '˛', 0xCF: 'ˇ', 0xD0: '—', 0xE1: 'Æ', 0xE3: 'ª', 0xE8: 'Ł', 0xE9: 'Ø', 0xEA: 'Œ',
	0xEB: 'º', 0xF1: 'æ', 0xF5: 'ı', 0xF8: 'ł', 0xF9: 'ø', 0xFA: 'œ', 0xFB: 'ß',
}

type pdfSimpleFont struct {
	table [256]string
}

func (f *pdfSimpleFont) decode(b []byte) []byte {
	var out []byte
	for _, c := range b {
		out = append(out, f.table[c]...)
	}
	return out
}

func pdfBaseEncoding(name string) (*pdfSimpleFont, bool) {
	f := &pdfSimpleFont{}
	for i := 0; i < 256; i++ {
		c := byte(i)
		var r rune
		switch name {
		case "WinAnsiEncoding":
			r = rune(cp1252ToUnicode(c))
		case "MacRomanEncoding":
			r = charmap.Macintosh.DecodeByte(c)
		case "StandardEncoding":
			if v, ok := pdfStandardHigh[c]; ok {
				r = v
			} else if c < 0x80 {
				r = rune(c)
			}
		default:
			return nil, false
		}
		if r >= 0x20 && r != 0x7F {
			f.table[i] = string(r)
		}
	}
	return f, true
}

var (
	pdfEncodingKey = regexp.MustCompile(`/Encoding\s*`)
	pdfBaseEncKey  = regexp.MustCompile(`/BaseEncoding\s*/(\w+)`)
	pdfDiffKey     = regexp.MustCompile(`/Differences\s*`)
	pdfSubtypeKey  = regexp.MustCompile(`/Subtype\s*/(\w+)`)
	pdfDescendants = regexp.MustCompile(`/DescendantFonts\s*`)
	pdfDescriptor  = regexp.MustCompile(`/FontDescriptor\s+(\d+)\s+\d+\s+R`)
	pdfFontFile2   = regexp.MustCompile(`/FontFile2\s+(\d+)\s+\d+\s+R`)
	pdfCIDToGID    = regexp.MustCompile(`/CIDToGIDMap\s*`)
	pdfDiffToken   = regexp.MustCompile(`(\d+)|/([^\s/<>\[\]()]+)`)
)

// pdfSimpleEncoding builds the byte table of a simple font's /Encoding, or
// nil when the font declares none (its bytes are then shown as-is).
func pdfSimpleEncoding(fontDict []byte, objs map[int]*pdfObject) pdfFont {
	loc := pdfEncodingKey.FindIndex(fontDict)
	if loc == nil {
		return nil
	}
	rest := fontDict[loc[1]:]
	if m := pdfNameTok.FindSubmatch(rest); m != nil {
		if f, ok := pdfBaseEncoding(string(m[1])); ok {
			return f
		}
		return nil
	}
	enc := pdfValueAfter(fontDict, pdfEncodingKey, objs)
	if enc == nil {
		return nil
	}
	base := "StandardEncoding"
	if m := pdfBaseEncKey.FindSubmatch(enc); m != nil {
		base = string(m[1])
	}
	f, ok := pdfBaseEncoding(base)
	if !ok {
		f, _ = pdfBaseEncoding("StandardEncoding")
	}
	if dl := pdfDiffKey.FindIndex(enc); dl != nil {
		arr := pdfBalanced(enc[dl[1]:])
		code := -1
		for _, m := range pdfDiffToken.FindAllSubmatch(arr, 4096) {
			if m[1] != nil {
				code, _ = strconv.Atoi(string(m[1]))
				continue
			}
			if code >= 0 && code < 256 {
				f.table[code] = glyphNameToUnicode(string(m[2]))
				code++
			}
		}
	}
	return f
}

// pdfGlyphFont decodes 2-byte CIDs through CIDToGIDMap and the inverted
// Unicode cmap of an embedded TrueType program.
type pdfGlyphFont struct {
	cidToGID []uint16 // nil: identity
	gidToU   map[uint16]rune
}

func (f *pdfGlyphFont) decode(b []byte) []byte {
	var out []byte
	for i := 0; i+1 < len(b); i += 2 {
		gid := binary.BigEndian.Uint16(b[i:])
		if f.cidToGID != nil {
			if int(gid) >= len(f.cidToGID) {
				continue
			}
			gid = f.cidToGID[gid]
		}
		if r, ok := f.gidToU[gid]; ok {
			out = utf8.AppendRune(out, r)
		}
	}
	return out
}

func pdfRefNum(m [][]byte) int {
	if m == nil {
		return -1
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// pdfType0Glyphs builds a decoder for a Type0 font with an Identity
// encoding and an embedded TrueType program; nil otherwise.
func pdfType0Glyphs(fontDict []byte, objs map[int]*pdfObject) pdfFont {
	if !bytes.Contains(fontDict, []byte("/Identity-H")) && !bytes.Contains(fontDict, []byte("/Identity-V")) {
		return nil
	}
	desc := pdfValueAfter(fontDict, pdfDescendants, objs)
	if arr := pdfBalanced(bytes.TrimLeft(desc, " \t\r\n")); len(arr) > 0 && arr[0] == '[' {
		if m := pdfRefAll.FindSubmatch(arr); m != nil {
			if o := objs[pdfRefNum(m)]; o != nil {
				desc = o.dict
			}
		}
	}
	fd := objs[pdfRefNum(pdfDescriptor.FindSubmatch(desc))]
	if fd == nil {
		return nil
	}
	ff := objs[pdfRefNum(pdfFontFile2.FindSubmatch(fd.dict))]
	if ff == nil || !ff.hasStream || ff.stream == nil {
		return nil
	}
	gidToU := trueTypeGlyphUnicode(ff.stream)
	if len(gidToU) == 0 {
		return nil
	}
	f := &pdfGlyphFont{gidToU: gidToU}
	if loc := pdfCIDToGID.FindIndex(desc); loc != nil {
		if m := pdfRefRe.FindSubmatch(desc[loc[1]:]); m != nil {
			if o := objs[pdfRefNum(m)]; o != nil && o.hasStream {
				f.cidToGID = make([]uint16, len(o.stream)/2)
				for i := range f.cidToGID {
					f.cidToGID[i] = binary.BigEndian.Uint16(o.stream[2*i:])
				}
			}
		}
	}
	return f
}

// trueTypeGlyphUnicode inverts the (3,1)/(0,x) format 4 or (3,10) format 12
// cmap subtable of an sfnt program into glyph id → code point.
func trueTypeGlyphUnicode(font []byte) map[uint16]rune {
	if len(font) < 12 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(font[4:]))
	var cmap []byte
	for i := 0; i < n && 12+16*i+16 <= len(font); i++ {
		rec := font[12+16*i:]
		if string(rec[:4]) == "cmap" {
			off, l := int(binary.BigEndian.Uint32(rec[8:])), int(binary.BigEndian.Uint32(rec[12:]))
			if off >= 0 && l >= 0 && off+l <= len(font) && off+l >= off {
				cmap = font[off : off+l]
			}
		}
	}
	if len(cmap) < 4 {
		return nil
	}
	var best []byte
	bestScore := 0
	count := int(binary.BigEndian.Uint16(cmap[2:]))
	for i := 0; i < count && 4+8*i+8 <= len(cmap); i++ {
		rec := cmap[4+8*i:]
		pid, eid := binary.BigEndian.Uint16(rec), binary.BigEndian.Uint16(rec[2:])
		off := int(binary.BigEndian.Uint32(rec[4:]))
		if off < 0 || off+4 > len(cmap) {
			continue
		}
		score := 0
		switch {
		case pid == 3 && eid == 10, pid == 0 && eid >= 4:
			score = 3
		case pid == 3 && eid == 1, pid == 0:
			score = 2
		}
		if score > bestScore {
			best, bestScore = cmap[off:], score
		}
	}
	if best == nil {
		return nil
	}
	out := map[uint16]rune{}
	add := func(r rune, gid uint16) {
		if _, seen := out[gid]; !seen && gid != 0 && r >= 0x20 && utf8.ValidRune(r) && len(out) < 65536 {
			out[gid] = r
		}
	}
	switch binary.BigEndian.Uint16(best) {
	case 4:
		if len(best) < 14 {
			return nil
		}
		seg := int(binary.BigEndian.Uint16(best[6:])) / 2
		if 16+8*seg > len(best) {
			return nil
		}
		budget := 1 << 20 // total code points walked across segments
		ends, starts := best[14:], best[16+2*seg:]
		deltas, ranges := best[16+4*seg:], best[16+6*seg:]
		for s := 0; s < seg; s++ {
			end, start := int(binary.BigEndian.Uint16(ends[2*s:])), int(binary.BigEndian.Uint16(starts[2*s:]))
			delta, ro := binary.BigEndian.Uint16(deltas[2*s:]), int(binary.BigEndian.Uint16(ranges[2*s:]))
			for c := start; c <= end && c < 0xFFFF && budget > 0; c++ {
				budget--
				var gid uint16
				if ro == 0 {
					gid = uint16(c) + delta
				} else {
					p := 16 + 6*seg + 2*s + ro + 2*(c-start)
					if p+2 > len(best) {
						break
					}
					if gid = binary.BigEndian.Uint16(best[p:]); gid != 0 {
						gid += delta
					}
				}
				add(rune(c), gid)
			}
		}
	case 12:
		if len(best) < 16 {
			return nil
		}
		groups := int(binary.BigEndian.Uint32(best[12:]))
		for g := 0; g < groups && 16+12*g+12 <= len(best); g++ {
			p := best[16+12*g:]
			start, end, gid := binary.BigEndian.Uint32(p), binary.BigEndian.Uint32(p[4:]), binary.BigEndian.Uint32(p[8:])
			for c := start; c <= end && c-start < 65536 && len(out) < 65536; c++ {
				add(rune(c), uint16(gid+(c-start)))
			}
		}
	}
	return out
}
