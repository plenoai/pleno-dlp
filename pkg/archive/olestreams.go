package archive

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

// OLE stream payloads that are not document text:
//   - \x01Ole10Native wraps a file embedded through OLE Packager
//     (ObjectPool/_NNN storages in Word, embedded objects elsewhere). The
//     header (label, source path, temp path) precedes the payload, so the
//     payload is unwrapped and walked as a nested member.
//   - \x05SummaryInformation and \x05DocumentSummaryInformation are
//     property sets ([MS-OLEPS]); only their string properties are text.

const (
	oleNativeStream  = "\x01Ole10Native"
	oleSummaryStream = "\x05SummaryInformation"
	oleDocSummary    = "\x05DocumentSummaryInformation"
	oleMaxNameBytes  = 1024
)

// oleMetadataStream reports class and link metadata streams that hold no
// user content (CLSIDs, clipboard formats, object flags).
func oleMetadataStream(base string) bool {
	switch base {
	case "\x01CompObj", "\x03ObjInfo", "\x01Ole":
		return true
	}
	return false
}

// parseOle10Native returns the embedded file name and payload. Layout (as
// written by OLE Packager): total size u32, flags u16, label\0, source
// path\0, two u32 fields, temp path\0, payload size u32, payload.
func parseOle10Native(b []byte) (string, []byte, error) {
	errBad := errors.New("malformed Ole10Native stream")
	if len(b) < 6 {
		return "", nil, errBad
	}
	// The total size counts the bytes after itself; streams are padded.
	total := int64(binary.LittleEndian.Uint32(b))
	if total < 2 || total > int64(len(b)-4) {
		return "", nil, errBad
	}
	b = b[:4+total]
	p := 6
	cstr := func() (string, bool) {
		end := bytes.IndexByte(b[p:min(len(b), p+oleMaxNameBytes)], 0)
		if end < 0 {
			return "", false
		}
		s := string(b[p : p+end])
		p += end + 1
		return s, true
	}
	label, ok := cstr()
	if !ok {
		return "", nil, errBad
	}
	src, ok := cstr()
	if !ok || p+8 > len(b) {
		return "", nil, errBad
	}
	p += 8
	if _, ok := cstr(); !ok || p+4 > len(b) {
		return "", nil, errBad
	}
	n := int64(binary.LittleEndian.Uint32(b[p:]))
	p += 4
	if n > int64(len(b)-p) {
		return "", nil, errBad
	}
	name := label
	if name == "" {
		name = src
	}
	// Keep the base name only; the source path is the packager's machine.
	if i := bytes.LastIndexAny([]byte(name), `\/`); i >= 0 {
		name = name[i+1:]
	}
	if name == "" || !utf8.ValidString(name) {
		name = "embedded"
	}
	return name, b[p : p+int(n)], nil
}

// Property types ([MS-OLEPS] 2.15).
const (
	vtI2      = 0x0002
	vtLPSTR   = 0x001E
	vtLPWSTR  = 0x001F
	vtVariant = 0x000C
	vtVector  = 0x1000
	cpUTF16   = 1200
	cpUTF8    = 65001
)

// extractPropertySetText writes the string properties of every section of
// a property set stream, and the property names of user-defined sections.
func extractPropertySetText(b []byte, out *textBuffer) error {
	if len(b) < 28 || binary.LittleEndian.Uint16(b) != 0xFFFE {
		return errors.New("not an OLE property set")
	}
	sections := int(binary.LittleEndian.Uint32(b[24:]))
	if sections > 16 || 28+20*sections > len(b) {
		return errors.New("property set section list out of range")
	}
	for i := 0; i < sections && !out.overflow; i++ {
		off := int(binary.LittleEndian.Uint32(b[28+20*i+16:]))
		if off < 0 || off+8 > len(b) {
			return errors.New("property set section out of range")
		}
		sec := b[off:]
		if size := int(binary.LittleEndian.Uint32(sec)); size >= 8 && size <= len(sec) {
			sec = sec[:size]
		}
		count := int(binary.LittleEndian.Uint32(sec[4:]))
		if count > 4096 || 8+8*count > len(sec) {
			return errors.New("property set entries out of range")
		}
		codepage := 0
		for k := 0; k < count; k++ { // codepage (PID 1) decodes the strings
			id := binary.LittleEndian.Uint32(sec[8+8*k:])
			po := int(binary.LittleEndian.Uint32(sec[8+8*k+4:]))
			if id == 1 && po >= 0 && po+6 <= len(sec) && binary.LittleEndian.Uint16(sec[po:]) == vtI2 {
				codepage = int(binary.LittleEndian.Uint16(sec[po+4:]))
			}
		}
		for k := 0; k < count && !out.overflow; k++ {
			id := binary.LittleEndian.Uint32(sec[8+8*k:])
			po := int(binary.LittleEndian.Uint32(sec[8+8*k+4:]))
			if po < 0 || po+4 > len(sec) {
				continue
			}
			if id == 0 { // dictionary: user-defined property names
				propDictionary(sec[po:], codepage, out)
				continue
			}
			typ := binary.LittleEndian.Uint32(sec[po:])
			propValue(sec[po+4:], typ, codepage, out, 0)
		}
	}
	return nil
}

func propString(b []byte, wide bool, codepage int) (string, int, bool) {
	if len(b) < 4 {
		return "", 0, false
	}
	n := int(binary.LittleEndian.Uint32(b))
	if wide {
		if n < 0 || n > (len(b)-4)/2 {
			return "", 0, false
		}
		units := make([]uint16, n)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(b[4+2*i:])
		}
		size := 4 + 2*n
		return trimNul(string(utf16.Decode(units))), size + (4-size%4)%4, true
	}
	if n < 0 || n > len(b)-4 {
		return "", 0, false
	}
	raw := b[4 : 4+n]
	size := 4 + n
	return trimNul(decodeCodepage(raw, codepage)), size + (4-size%4)%4, true
}

func decodeCodepage(raw []byte, codepage int) string {
	switch codepage {
	case cpUTF16:
		units := make([]uint16, len(raw)/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(raw[2*i:])
		}
		return string(utf16.Decode(units))
	case cpUTF8:
		return string(raw)
	}
	// Other ANSI code pages: ASCII is common to all; cp1252 covers the
	// Western default. Bytes of other code pages degrade to Latin text.
	units := make([]uint16, len(raw))
	for i, c := range raw {
		units[i] = cp1252ToUnicode(c)
	}
	return string(utf16.Decode(units))
}

func trimNul(s string) string {
	for len(s) > 0 && s[len(s)-1] == 0 {
		s = s[:len(s)-1]
	}
	return s
}

// propValue writes a string, string vector, or variant vector value.
func propValue(b []byte, typ uint32, codepage int, out *textBuffer, depth int) int {
	write := func(s string) {
		if s != "" {
			out.writeString(s)
			out.writeByte('\n')
		}
	}
	switch typ {
	case vtLPSTR, vtLPWSTR:
		s, n, ok := propString(b, typ == vtLPWSTR, codepage)
		if !ok {
			return -1
		}
		write(s)
		return n
	case vtVector | vtLPSTR, vtVector | vtLPWSTR, vtVector | vtVariant:
		if len(b) < 4 || depth > 0 {
			return -1
		}
		count := int(binary.LittleEndian.Uint32(b))
		p := 4
		for i := 0; i < count && i < 4096 && p < len(b) && !out.overflow; i++ {
			elem := typ &^ vtVector
			if elem == vtVariant {
				if p+4 > len(b) {
					return -1
				}
				elem = binary.LittleEndian.Uint32(b[p:])
				p += 4
			}
			var n int
			switch elem {
			case vtLPSTR, vtLPWSTR:
				n = propValue(b[p:], elem, codepage, out, depth+1)
			case vtI2:
				n = 4
			case 0x0003: // VT_I4 (heading pair counts)
				n = 4
			default:
				return -1
			}
			if n < 0 {
				return -1
			}
			p += n
		}
		return p
	}
	return -1
}

// propDictionary writes the names of a user-defined property section.
func propDictionary(b []byte, codepage int, out *textBuffer) {
	if len(b) < 4 {
		return
	}
	count := int(binary.LittleEndian.Uint32(b))
	p := 4
	for i := 0; i < count && i < 4096 && p+8 <= len(b) && !out.overflow; i++ {
		p += 4 // property id
		n := int(binary.LittleEndian.Uint32(b[p:]))
		if codepage == cpUTF16 {
			n *= 2
		}
		if n < 0 || n > len(b)-p-4 {
			return
		}
		if s := trimNul(decodeCodepage(b[p+4:p+4+n], codepage)); s != "" {
			out.writeString(s)
			out.writeByte('\n')
		}
		p += 4 + n
		if codepage == cpUTF16 {
			p += (4 - p%4) % 4
		}
	}
}
