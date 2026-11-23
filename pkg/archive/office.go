package archive

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

// Text extraction for legacy binary Office documents (Word 97-2003,
// Excel BIFF8, PowerPoint 97-2003). Their main streams interleave document
// text with binary structures; handing those raw bytes to detectors (which
// also try a UTF-16LE decode) produces matches that straddle record
// boundaries. Only the document text is emitted for these streams, while
// every other OLE stream (embedded objects, macros, summary info) is still
// walked raw.

// Word: [MS-DOC] 2.5.1 FIB, 2.9.38 Clx, 2.9.177 PlcPcd, 2.9.178 Pcd.
const (
	wordFibFlagsOffset = 0x0A
	wordFibWhichTblStm = 0x0200
	wordFibEncrypted   = 0x0100
	wordFibFcClx       = 0x01A2
	wordFibLcbClx      = 0x01A6
	wordFcCompressed   = 0x40000000
	wordFibCcpText     = 0x4C // FibRgLw97.ccpText; ccpFtn, ccpHdd, reserved3, ccpAtn, ccpEdn, ccpTxbx, ccpHdrTxbx follow
)

// wordStories names the document parts in CP order ([MS-DOC] 2.4.1): each
// part after the main text gets its own derived entry.
var wordStories = []struct {
	suffix string
	field  int // offset of its ccp in the FIB; -1 for none
}{
	{extractedTextSuffix, wordFibCcpText},
	{"#footnotes", wordFibCcpText + 4},
	{"#headers", wordFibCcpText + 8},
	{"", wordFibCcpText + 12}, // reserved3 (macros), always 0
	{"#comments", wordFibCcpText + 16},
	{"#endnotes", wordFibCcpText + 20},
	{"#textboxes", wordFibCcpText + 24},
	{"#header-textboxes", wordFibCcpText + 28},
}

// wordStoryMark records where a story starts in the extracted text.
type wordStoryMark struct {
	suffix string
	offset int
}

// wordActiveTable returns the name of the table stream the FIB selects.
func wordActiveTable(word []byte) string {
	if len(word) > wordFibFlagsOffset+2 && binary.LittleEndian.Uint16(word[wordFibFlagsOffset:])&wordFibWhichTblStm != 0 {
		return "1Table"
	}
	return "0Table"
}

var errOfficeEncrypted = errors.New("password-protected Office document")

// extractWordStories decodes the piece table of a WordDocument stream using the
// table stream picked by the FIB.
// It also records, in marks, the text offset where each story (main text,
// footnotes, headers, comments, endnotes, text boxes) begins.
func extractWordStories(word []byte, tables map[string][]byte, out *textBuffer, marks *[]wordStoryMark) error {
	if len(word) < wordFibLcbClx+4 || binary.LittleEndian.Uint16(word) != 0xA5EC {
		return errors.New("not a Word 97 FIB")
	}
	flags := binary.LittleEndian.Uint16(word[wordFibFlagsOffset:])
	if flags&wordFibEncrypted != 0 {
		return errOfficeEncrypted
	}
	table := tables["0Table"]
	if flags&wordFibWhichTblStm != 0 {
		table = tables["1Table"]
	}
	fc := int64(binary.LittleEndian.Uint32(word[wordFibFcClx:]))
	lcb := int64(binary.LittleEndian.Uint32(word[wordFibLcbClx:]))
	if table == nil || fc+lcb > int64(len(table)) || lcb <= 0 {
		return errors.New("word: Clx out of range")
	}
	clx := table[fc : fc+lcb]
	for len(clx) > 0 && clx[0] == 0x01 { // Prc: grpprl modifiers
		if len(clx) < 3 {
			return errors.New("word: truncated Prc")
		}
		n := 3 + int(binary.LittleEndian.Uint16(clx[1:]))
		if n > len(clx) {
			return errors.New("word: truncated Prc")
		}
		clx = clx[n:]
	}
	if len(clx) < 5 || clx[0] != 0x02 {
		return errors.New("word: missing Pcdt")
	}
	plc := clx[5:]
	if l := int(binary.LittleEndian.Uint32(clx[1:])); l <= len(plc) {
		plc = plc[:l]
	}
	if len(plc) < 4 || (len(plc)-4)%12 != 0 {
		return errors.New("word: malformed PlcPcd")
	}
	n := (len(plc) - 4) / 12
	pcds := plc[4*(n+1):]
	// Story boundaries in CP space; without the FIB fields everything is
	// main text.
	// Only non-empty stories get a start; CPs past the last story (the
	// final paragraph mark) stay in it.
	type storyStart struct {
		cp  uint32
		idx int
	}
	var bounds []storyStart
	if len(word) >= wordFibCcpText+32 {
		var cp uint64
		for i, st := range wordStories {
			n := binary.LittleEndian.Uint32(word[st.field:])
			if n > 0 && cp <= 0xFFFFFFFF {
				bounds = append(bounds, storyStart{uint32(cp), i})
			}
			cp += uint64(n)
		}
	}
	if len(bounds) > 0 && bounds[0].cp != 0 {
		bounds = nil // main text must start at CP 0
	}
	story := -1
	var line []uint16
	flush := func() bool {
		if len(line) == 0 {
			return true
		}
		ok := out.writeString(string(utf16.Decode(line))) && out.writeByte('\n')
		line = line[:0]
		return ok
	}
	emit := func(cp uint32, c uint16) bool {
		next := story
		for next+1 < len(bounds) && cp >= bounds[next+1].cp {
			next++
		}
		if next != story {
			if !flush() {
				return false
			}
			story = next
			if suffix := wordStories[bounds[story].idx].suffix; marks != nil && suffix != "" {
				*marks = append(*marks, wordStoryMark{suffix, out.buf.Len()})
			}
		}
		switch {
		case c == '\r' || c == 0x0B || c == 0x0C || c == 0x07 || c == '\n':
			return flush()
		case c == '\t':
			line = append(line, ' ')
		case c < 0x20: // field marks, inline objects, footnote refs
		default:
			line = append(line, c)
		}
		return true
	}
	for i := 0; i < n; i++ {
		cpStart := binary.LittleEndian.Uint32(plc[4*i:])
		cpEnd := binary.LittleEndian.Uint32(plc[4*i+4:])
		if cpEnd < cpStart {
			return errors.New("word: decreasing CP")
		}
		chars := int64(cpEnd - cpStart)
		raw := binary.LittleEndian.Uint32(pcds[8*i+2:])
		if raw&wordFcCompressed != 0 {
			off := int64(raw&^wordFcCompressed) / 2
			if off > int64(len(word)) {
				continue // piece outside the stream (fast-save remnant)
			}
			chars = min(chars, int64(len(word))-off) // last piece may overrun the stream
			for j, b := range word[off : off+chars] {
				if !emit(cpStart+uint32(j), cp1252ToUnicode(b)) {
					return nil
				}
			}
			continue
		}
		off := int64(raw)
		if off > int64(len(word)) {
			continue // piece outside the stream (fast-save remnant)
		}
		chars = min(chars, (int64(len(word))-off)/2)
		for j := int64(0); j < chars; j++ {
			if !emit(cpStart+uint32(j), binary.LittleEndian.Uint16(word[off+2*j:])) {
				return nil
			}
		}
	}
	flush()
	return nil
}

// cp1252High maps 0x80-0x9F; the rest of cp1252 equals Latin-1.
var cp1252High = [32]uint16{
	0x20AC, 0x81, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x8D, 0x017D, 0x8F,
	0x90, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x9D, 0x017E, 0x0178,
}

func cp1252ToUnicode(b byte) uint16 {
	if b >= 0x80 && b < 0xA0 {
		return cp1252High[b-0x80]
	}
	return uint16(b)
}

// Excel: [MS-XLS] 2.4 records; SST (0x00FC) + CONTINUE (0x003C), LABEL
// (0x0204), and FORMULA string results (STRING 0x0207) carry cell text.
const (
	biffBOF      = 0x0809
	biffFilePass = 0x002F
	biffSST      = 0x00FC
	biffContinue = 0x003C
	biffLabel    = 0x0204
	biffString   = 0x0207
)

type biffRecord struct {
	typ  uint16
	data []byte
}

func extractBIFFText(stream []byte, out *textBuffer) error {
	var recs []biffRecord
	for p := 0; p+4 <= len(stream); {
		typ := binary.LittleEndian.Uint16(stream[p:])
		l := int(binary.LittleEndian.Uint16(stream[p+2:]))
		if p+4+l > len(stream) {
			return errors.New("xls: truncated record")
		}
		recs = append(recs, biffRecord{typ, stream[p+4 : p+4+l]})
		p += 4 + l
	}
	if len(recs) == 0 || recs[0].typ != biffBOF {
		return errors.New("xls: missing BOF")
	}
	for i := 0; i < len(recs) && !out.overflow; i++ {
		r := recs[i]
		switch r.typ {
		case biffFilePass:
			return errOfficeEncrypted
		case biffSST:
			parts := [][]byte{r.data}
			for i+1 < len(recs) && recs[i+1].typ == biffContinue {
				i++
				parts = append(parts, recs[i].data)
			}
			if len(r.data) < 8 {
				continue
			}
			c := &biffCursor{parts: parts, pos: 8}
			count := binary.LittleEndian.Uint32(r.data[4:])
			for k := uint32(0); k < count && !out.overflow; k++ {
				s, ok := c.unicodeString()
				if !ok {
					break
				}
				out.writeString(s)
				out.writeByte('\n')
			}
		case biffLabel:
			if len(r.data) > 6 {
				c := &biffCursor{parts: [][]byte{r.data}, pos: 6}
				if s, ok := c.unicodeString(); ok {
					out.writeString(s)
					out.writeByte('\n')
				}
			}
		case biffString:
			c := &biffCursor{parts: [][]byte{r.data}}
			if s, ok := c.unicodeString(); ok {
				out.writeString(s)
				out.writeByte('\n')
			}
		}
	}
	return nil
}

// biffCursor reads XLUnicodeRichExtendedString values that may continue
// across CONTINUE records; a continued character run restarts with a fresh
// fHighByte option byte.
type biffCursor struct {
	parts [][]byte
	idx   int
	pos   int
}

func (c *biffCursor) advance() bool {
	for c.idx < len(c.parts) && c.pos >= len(c.parts[c.idx]) {
		c.idx++
		c.pos = 0
	}
	return c.idx < len(c.parts)
}

func (c *biffCursor) bytes(n int) ([]byte, bool) {
	var b []byte
	for n > 0 {
		if !c.advance() {
			return nil, false
		}
		part := c.parts[c.idx][c.pos:]
		take := min(n, len(part))
		b = append(b, part[:take]...)
		c.pos += take
		n -= take
	}
	return b, true
}

func (c *biffCursor) unicodeString() (string, bool) {
	h, ok := c.bytes(3)
	if !ok {
		return "", false
	}
	chars := int(binary.LittleEndian.Uint16(h))
	flags := h[2]
	var runs, ext int
	if flags&0x08 != 0 {
		b, ok := c.bytes(2)
		if !ok {
			return "", false
		}
		runs = int(binary.LittleEndian.Uint16(b))
	}
	if flags&0x04 != 0 {
		b, ok := c.bytes(4)
		if !ok {
			return "", false
		}
		ext = int(binary.LittleEndian.Uint32(b))
	}
	high := flags&0x01 != 0
	units := make([]uint16, 0, chars)
	for len(units) < chars {
		if !c.advance() {
			return "", false
		}
		if c.pos == 0 && len(units) > 0 { // continued run: new option byte
			high = c.parts[c.idx][0]&0x01 != 0
			c.pos = 1
			continue
		}
		part := c.parts[c.idx][c.pos:]
		if high {
			for len(part) >= 2 && len(units) < chars {
				units = append(units, binary.LittleEndian.Uint16(part))
				part = part[2:]
				c.pos += 2
			}
			if len(part) == 1 { // a split code unit is malformed
				return "", false
			}
		} else {
			for len(part) > 0 && len(units) < chars {
				units = append(units, cp1252ToUnicode(part[0]))
				part = part[1:]
				c.pos++
			}
		}
	}
	// Formatting runs and phonetic data follow the text; a truncated tail
	// only ends the table, the decoded text is still valid.
	_, _ = c.bytes(4*runs + ext)
	return string(utf16.Decode(units)), true
}

// PowerPoint: [MS-PPT] 2.3.1 RecordHeader; containers have recVer 0xF.
const (
	pptTextChars  = 0x0FA0
	pptTextBytes  = 0x0FA8
	pptCString    = 0x0FBA
	pptCryptoInfo = 0x2F14
)

func extractPPTText(stream []byte, out *textBuffer) error {
	found := false
	for p := 0; p+8 <= len(stream) && !out.overflow; {
		verInst := binary.LittleEndian.Uint16(stream[p:])
		typ := binary.LittleEndian.Uint16(stream[p+2:])
		l := int64(binary.LittleEndian.Uint32(stream[p+4:]))
		p += 8
		if verInst&0x0F == 0x0F { // container: descend into its body
			found = true
			continue
		}
		if int64(p)+l > int64(len(stream)) {
			if !found {
				return errors.New("ppt: truncated record")
			}
			return nil
		}
		body := stream[p : p+int(l)]
		p += int(l)
		found = true
		var text []uint16
		switch typ {
		case pptCryptoInfo:
			return errOfficeEncrypted
		case pptTextChars, pptCString:
			for i := 0; i+1 < len(body); i += 2 {
				text = append(text, binary.LittleEndian.Uint16(body[i:]))
			}
		case pptTextBytes:
			for _, b := range body {
				text = append(text, uint16(b))
			}
		default:
			continue
		}
		for i, u := range text {
			if u == '\r' || u == 0x0B {
				text[i] = '\n'
			}
		}
		if len(text) > 0 {
			out.writeString(string(utf16.Decode(text)))
			out.writeByte('\n')
		}
	}
	return nil
}
