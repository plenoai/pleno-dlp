package archive

import (
	"bytes"
	"regexp"
	"sort"
	"strconv"
	"unicode/utf16"
)

// ToUnicode CMap support (PDF 32000-1:2008 §9.10.3). Fonts with custom
// encodings (subset TrueType, CID/Type0 Identity-H) show glyph codes, not
// characters; their /ToUnicode stream maps codes back to Unicode. Pages are
// located through a light object index (top-level objects and object
// streams), each page's /Font resources are bound to their CMaps, and the
// page content streams are decoded with the font selected by Tf.

const (
	pdfMaxObjects      = 100_000
	pdfMaxCMapRanges   = 65_536
	pdfMaxCMapBytes    = 4 << 20
	pdfMaxObjStmHeader = 1 << 20
)

type cmapRange struct {
	lo, hi uint32
	n      int      // code length in bytes
	dst    []uint16 // incremented by code-lo (dst-string form)
	arr    [][]uint16
}

type pdfCMap struct {
	space  []cmapRange // codespace ranges (dst unused)
	ranges []cmapRange // bfchar entries are one-code ranges
}

func pdfHexUnits(b []byte) []uint16 {
	raw := pdfHex(b)
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = uint16(raw[2*i])<<8 | uint16(raw[2*i+1])
	}
	return u
}

func pdfHexCode(b []byte) (uint32, int) {
	raw := pdfHex(b)
	if len(raw) == 0 || len(raw) > 4 {
		return 0, 0
	}
	var v uint32
	for _, c := range raw {
		v = v<<8 | uint32(c)
	}
	return v, len(raw)
}

// cmapTokens splits CMap syntax into hex strings, arrays brackets, and words.
func cmapTokens(data []byte) [][]byte {
	var toks [][]byte
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '%':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		case c == '<' && i+1 < len(data) && data[i+1] == '<', c == '>' && i+1 < len(data) && data[i+1] == '>':
			i += 2
		case c == '<':
			end := bytes.IndexByte(data[i:], '>')
			if end < 0 {
				return toks
			}
			toks = append(toks, data[i:i+end+1])
			i += end + 1
		case c == '[' || c == ']':
			toks = append(toks, data[i:i+1])
			i++
		case c == '(':
			_, n := pdfLiteral(data[i:])
			i += n
		case isPDFRegular(c):
			j := i
			for j < len(data) && isPDFRegular(data[j]) {
				j++
			}
			toks = append(toks, data[i:j])
			i = j
		default:
			i++
		}
	}
	return toks
}

func isHexTok(t []byte) bool { return len(t) >= 2 && t[0] == '<' }

func parseCMap(data []byte) *pdfCMap {
	if len(data) > pdfMaxCMapBytes {
		data = data[:pdfMaxCMapBytes]
	}
	m := &pdfCMap{}
	toks := cmapTokens(data)
	mode := ""
	for i := 0; i < len(toks) && len(m.ranges) < pdfMaxCMapRanges; i++ {
		t := string(toks[i])
		switch t {
		case "begincodespacerange", "beginbfchar", "beginbfrange":
			mode = t
			continue
		case "endcodespacerange", "endbfchar", "endbfrange":
			mode = ""
			continue
		}
		switch mode {
		case "begincodespacerange":
			if i+1 < len(toks) && isHexTok(toks[i]) && isHexTok(toks[i+1]) {
				lo, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
				hi, n2 := pdfHexCode(toks[i+1][1 : len(toks[i+1])-1])
				if n > 0 && n == n2 {
					m.space = append(m.space, cmapRange{lo: lo, hi: hi, n: n})
				}
				i++
			}
		case "beginbfchar":
			if i+1 < len(toks) && isHexTok(toks[i]) && isHexTok(toks[i+1]) {
				code, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
				if n > 0 {
					m.ranges = append(m.ranges, cmapRange{lo: code, hi: code, n: n, dst: pdfHexUnits(toks[i+1][1 : len(toks[i+1])-1])})
				}
				i++
			}
		case "beginbfrange":
			if i+2 >= len(toks) || !isHexTok(toks[i]) || !isHexTok(toks[i+1]) {
				continue
			}
			lo, n := pdfHexCode(toks[i][1 : len(toks[i])-1])
			hi, n2 := pdfHexCode(toks[i+1][1 : len(toks[i+1])-1])
			r := cmapRange{lo: lo, hi: hi, n: n}
			i += 2
			if isHexTok(toks[i]) {
				r.dst = pdfHexUnits(toks[i][1 : len(toks[i])-1])
			} else if string(toks[i]) == "[" {
				for i+1 < len(toks) && string(toks[i+1]) != "]" {
					i++
					if isHexTok(toks[i]) && len(r.arr) < pdfMaxCMapRanges {
						r.arr = append(r.arr, pdfHexUnits(toks[i][1:len(toks[i])-1]))
					}
				}
				i++
			}
			if n > 0 && n == n2 && lo <= hi && (len(r.dst) > 0 || len(r.arr) > 0) {
				m.ranges = append(m.ranges, r)
			}
		}
	}
	if len(m.ranges) == 0 {
		return nil
	}
	sort.SliceStable(m.ranges, func(a, b int) bool { return m.ranges[a].lo < m.ranges[b].lo })
	return m
}

// lookup returns the Unicode for code of length n.
func (m *pdfCMap) lookup(code uint32, n int) ([]uint16, bool) {
	i := sort.Search(len(m.ranges), func(k int) bool { return m.ranges[k].lo > code })
	for k := i - 1; k >= 0 && k >= i-8; k-- {
		r := m.ranges[k]
		if r.n != n || code < r.lo || code > r.hi {
			continue
		}
		off := code - r.lo
		if r.arr != nil {
			if int(off) < len(r.arr) {
				return r.arr[off], true
			}
			return nil, false
		}
		if len(r.dst) == 0 {
			return nil, false
		}
		out := append([]uint16(nil), r.dst...)
		out[len(out)-1] += uint16(off)
		return out, true
	}
	return nil, false
}

// codeLen picks the code length for the bytes at b using the codespace
// ranges; without them the mapping's own code lengths are tried.
func (m *pdfCMap) codeLen(b []byte) int {
	for n := 1; n <= 4 && n <= len(b); n++ {
		var v uint32
		for _, c := range b[:n] {
			v = v<<8 | uint32(c)
		}
		if len(m.space) > 0 {
			for _, r := range m.space {
				if r.n == n && v >= r.lo && v <= r.hi {
					return n
				}
			}
			continue
		}
		if _, ok := m.lookup(v, n); ok {
			return n
		}
	}
	if len(m.space) > 0 {
		return m.space[0].n
	}
	return 1
}

func (m *pdfCMap) decode(b []byte) []byte {
	var units []uint16
	for len(b) > 0 {
		n := min(m.codeLen(b), len(b))
		var v uint32
		for _, c := range b[:n] {
			v = v<<8 | uint32(c)
		}
		if u, ok := m.lookup(v, n); ok {
			for _, c := range u {
				if c >= 0x20 || c == '\t' || c == '\n' { // Skia maps ActualText glyphs to controls
					units = append(units, c)
				}
			}
		}
		b = b[n:]
	}
	return []byte(string(utf16.Decode(units)))
}

// pdfObject is one indirect object: its dictionary text and decoded stream.
type pdfObject struct {
	dict      []byte
	stream    []byte
	hasStream bool
	streamPos int // offset of the stream body in the file, -1 for ObjStm members
}

var (
	pdfObjHeader = regexp.MustCompile(`(\d+)\s+\d+\s+obj\b`)
	pdfRefRe     = regexp.MustCompile(`^\s*(\d+)\s+\d+\s+R`)
	pdfIntAfter  = func(key string) *regexp.Regexp { return regexp.MustCompile(key + `\s+(\d+)`) }
	pdfNKey      = pdfIntAfter(`/N`)
	pdfFirstKey  = pdfIntAfter(`/First`)
	pdfTypeObjS  = regexp.MustCompile(`/Type\s*/ObjStm\b`)
	pdfTypePage  = regexp.MustCompile(`/Type\s*/Page\b`)
	pdfFontRes   = regexp.MustCompile(`/Font\s*`)
	pdfToUnicode = regexp.MustCompile(`/ToUnicode\s+(\d+)\s+\d+\s+R`)
	pdfContents  = regexp.MustCompile(`/Contents\s*`)
	pdfResources = regexp.MustCompile(`/Resources\s*`)
	pdfDictEntry = regexp.MustCompile(`/([^\s/<>\[\]()]+)\s+(\d+)\s+\d+\s+R`)
	pdfRefAll    = regexp.MustCompile(`(\d+)\s+\d+\s+R`)
)

// indexPDFObjects collects top-level objects and object-stream members.
func indexPDFObjects(data []byte) map[int]*pdfObject {
	objs := map[int]*pdfObject{}
	locs := pdfObjHeader.FindAllSubmatchIndex(data, pdfMaxObjects)
	for k, loc := range locs {
		num, err := strconv.Atoi(string(data[loc[2]:loc[3]]))
		if err != nil {
			continue
		}
		end := len(data)
		if k+1 < len(locs) {
			end = locs[k+1][0]
		}
		body := data[loc[1]:end]
		if e := bytes.Index(body, []byte("endobj")); e >= 0 {
			body = body[:e]
		}
		o := &pdfObject{dict: body, streamPos: -1}
		if s := pdfStreamKeyword.FindIndex(body); s != nil && (s[0] < 3 || string(body[s[0]-3:s[0]]) != "end") {
			o.dict = body[:s[0]]
			raw := body[s[1]:]
			if e := bytes.Index(raw, []byte("endstream")); e >= 0 {
				raw = raw[:e]
			}
			raw = bytes.TrimRight(raw, "\r\n")
			o.hasStream = true
			o.streamPos = loc[1] + s[1]
			if decoded, ok, _ := pdfDecodeStream(o.dict, raw); ok {
				o.stream = decoded
			}
		}
		objs[num] = o
	}
	for _, o := range objs {
		if !o.hasStream || !pdfTypeObjS.Match(o.dict) {
			continue
		}
		n, first := pdfDictInt(o.dict, pdfNKey), pdfDictInt(o.dict, pdfFirstKey)
		if n <= 0 || first <= 0 || first > len(o.stream) || first > pdfMaxObjStmHeader || len(objs) >= pdfMaxObjects {
			continue
		}
		fields := bytes.Fields(o.stream[:first])
		for i := 0; i+1 < len(fields) && i/2 < n; i += 2 {
			num, err1 := strconv.Atoi(string(fields[i]))
			off, err2 := strconv.Atoi(string(fields[i+1]))
			if err1 != nil || err2 != nil || first+off > len(o.stream) {
				continue
			}
			end := len(o.stream)
			if i+3 < len(fields) {
				if next, err := strconv.Atoi(string(fields[i+3])); err == nil && first+next >= first+off && first+next <= len(o.stream) {
					end = first + next
				}
			}
			if _, exists := objs[num]; !exists {
				objs[num] = &pdfObject{dict: o.stream[first+off : end], streamPos: -1}
			}
		}
	}
	return objs
}

func pdfDictInt(dict []byte, re *regexp.Regexp) int {
	m := re.FindSubmatch(dict)
	if m == nil {
		return 0
	}
	v, _ := strconv.Atoi(string(m[1]))
	return v
}

// pdfValueAfter returns the dictionary value following key: the referenced
// object's text for an indirect reference, or the inline << >> / [ ] value.
func pdfValueAfter(dict []byte, key *regexp.Regexp, objs map[int]*pdfObject) []byte {
	loc := key.FindIndex(dict)
	if loc == nil {
		return nil
	}
	rest := dict[loc[1]:]
	if m := pdfRefRe.FindSubmatch(rest); m != nil {
		num, _ := strconv.Atoi(string(m[1]))
		if o := objs[num]; o != nil {
			return o.dict
		}
		return nil
	}
	return pdfBalanced(rest)
}

// pdfBalanced returns a leading << >> dictionary or [ ] array.
func pdfBalanced(b []byte) []byte {
	if len(b) == 0 || (b[0] != '<' && b[0] != '[') {
		return nil
	}
	depth := 0
	for i := 0; i < len(b); i++ {
		switch {
		case b[i] == '(':
			_, n := pdfLiteral(b[i:])
			i += n - 1
		case b[i] == '[', b[i] == '<' && i+1 < len(b) && b[i+1] == '<':
			depth++
			if b[i] == '<' {
				i++
			}
		case b[i] == ']', b[i] == '>' && i+1 < len(b) && b[i+1] == '>':
			depth--
			if b[i] == '>' {
				i++
			}
			if depth == 0 {
				return b[:i+1]
			}
		}
	}
	return b
}

// pdfFontMaps binds font resource names to decoders: the ToUnicode CMap
// when present, else an embedded TrueType cmap (Type0) or the simple-font
// /Encoding (pdffont.go).
func pdfFontMaps(fontDict []byte, objs map[int]*pdfObject, cache map[int]pdfFont) map[string]pdfFont {
	fonts := map[string]pdfFont{}
	for _, m := range pdfDictEntry.FindAllSubmatch(fontDict, 4096) {
		num, _ := strconv.Atoi(string(m[2]))
		font, seen := cache[num]
		if !seen {
			font = pdfFontDecoder(objs, num)
			cache[num] = font
		}
		if font != nil {
			fonts[string(m[1])] = font
		}
	}
	return fonts
}

func pdfFontDecoder(objs map[int]*pdfObject, num int) pdfFont {
	font := objs[num]
	if font == nil {
		return nil
	}
	if tu := pdfToUnicode.FindSubmatch(font.dict); tu != nil {
		cnum, _ := strconv.Atoi(string(tu[1]))
		if o := objs[cnum]; o != nil && o.hasStream {
			if cm := parseCMap(o.stream); cm != nil {
				return cm
			}
		}
	}
	sub := pdfSubtypeKey.FindSubmatch(font.dict)
	if sub != nil && string(sub[1]) == "Type0" {
		if f := pdfType0Glyphs(font.dict, objs); f != nil {
			return f
		}
		if f := pdfType0Ordering(font.dict, objs); f != nil {
			return f
		}
		if f := pdfType0Predefined(font.dict); f != nil {
			return f
		}
		// CIDs without any Unicode mapping are glyph indices, not text;
		// emitting their bytes only adds noise.
		return pdfDropFont{}
	}
	return pdfSimpleEncoding(font.dict, objs)
}

const pdfMaxPageTreeDepth = 32
const pdfMaxFormDepth = 8

var (
	pdfParentKey  = regexp.MustCompile(`/Parent\s+(\d+)\s+\d+\s+R`)
	pdfXObjectKey = regexp.MustCompile(`/XObject\s*`)
	pdfFormType   = regexp.MustCompile(`/Subtype\s*/Form\b`)
)

// pdfPageResources returns the page's /Resources, inherited from the
// nearest /Pages ancestor when the page has none (§7.7.3.4).
func pdfPageResources(page *pdfObject, objs map[int]*pdfObject) []byte {
	d := page.dict
	for depth := 0; depth < pdfMaxPageTreeDepth && d != nil; depth++ {
		if res := pdfValueAfter(d, pdfResources, objs); res != nil {
			return res
		}
		parent := objs[pdfRefNum(pdfParentKey.FindSubmatch(d))]
		if parent == nil {
			return nil
		}
		d = parent.dict
	}
	return nil
}

type pdfPageWalker struct {
	objs    map[int]*pdfObject
	cache   map[int]pdfFont
	handled map[int]bool
	out     *textBuffer
}

func (w *pdfPageWalker) fonts(res []byte) map[string]pdfFont {
	return pdfFontMaps(pdfValueAfter(res, pdfFontRes, w.objs), w.objs, w.cache)
}

func (w *pdfPageWalker) forms(res []byte) map[string]int {
	forms := map[string]int{}
	for _, m := range pdfDictEntry.FindAllSubmatch(pdfValueAfter(res, pdfXObjectKey, w.objs), 4096) {
		num, _ := strconv.Atoi(string(m[2]))
		if o := w.objs[num]; o != nil && o.hasStream && pdfFormType.Match(o.dict) {
			forms[string(m[1])] = num
		}
	}
	return forms
}

// render decodes one content stream with its resources; Do on a form
// XObject renders the form's stream with the form's own resources (falling
// back to the invoking resources), once per stream.
func (w *pdfPageWalker) render(stream, res []byte, depth int) {
	fonts := w.fonts(res)
	forms := w.forms(res)
	do := func(name string) {
		num, ok := forms[name]
		if !ok || depth >= pdfMaxFormDepth {
			return
		}
		o := w.objs[num]
		if o.stream == nil || w.handled[o.streamPos] {
			return
		}
		w.handled[o.streamPos] = true
		formRes := pdfValueAfter(o.dict, pdfResources, w.objs)
		if formRes == nil {
			formRes = res
		}
		w.render(o.stream, formRes, depth+1)
	}
	pdfStringsWithFonts(stream, fonts, do, w.out)
}

// pdfPageText decodes every page whose resources bind a decodable font or a
// form XObject and returns the stream offsets it consumed so the generic
// pass skips them.
func pdfPageText(objs map[int]*pdfObject, out *textBuffer) map[int]bool {
	w := &pdfPageWalker{objs: objs, cache: map[int]pdfFont{}, handled: map[int]bool{}, out: out}
	nums := make([]int, 0, len(objs))
	for n := range objs {
		nums = append(nums, n)
	}
	sort.Ints(nums)
	for _, n := range nums {
		page := objs[n]
		if !pdfTypePage.Match(page.dict) || out.overflow {
			continue
		}
		res := pdfPageResources(page, objs)
		if len(w.fonts(res)) == 0 && len(w.forms(res)) == 0 {
			continue
		}
		var contents []int
		if loc := pdfContents.FindIndex(page.dict); loc != nil {
			rest := page.dict[loc[1]:]
			if m := pdfRefRe.FindSubmatch(rest); m != nil {
				num, _ := strconv.Atoi(string(m[1]))
				if o := objs[num]; o != nil && !o.hasStream { // indirect array
					rest = o.dict
				} else {
					contents = append(contents, num)
					rest = nil
				}
			}
			if arr := pdfBalanced(bytes.TrimLeft(rest, " \t\r\n")); arr != nil {
				for _, m := range pdfRefAll.FindAllSubmatch(arr, 4096) {
					num, _ := strconv.Atoi(string(m[1]))
					contents = append(contents, num)
				}
			}
		}
		var stream []byte
		for _, c := range contents {
			if o := objs[c]; o != nil && o.hasStream && o.stream != nil && !w.handled[o.streamPos] && len(stream)+len(o.stream) <= pdfMaxStreamBytes {
				stream = append(append(stream, o.stream...), '\n')
				w.handled[o.streamPos] = true
			}
		}
		w.render(stream, res, 0)
	}
	return w.handled
}
