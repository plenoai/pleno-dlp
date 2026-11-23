package archive

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Python .pyc/.pyo string-constant extraction. The marshal stream is walked
// with an explicit work stack (never executed, never recursive in Go) and
// every str/bytes constant is emitted on its own line. Layouts follow
// CPython Python/marshal.c for 3.0 through 3.14.

type pycFormat struct {
	header          int
	leadingLongs    int
	middleObjects   int
	trailingObjects int
}

func pycVersion(magic uint16) (pycFormat, bool) {
	switch {
	case magic >= 3000 && magic <= 3189:
		return pycFormat{8, 5, 8, 1}, true
	case magic >= 3190 && magic <= 3379:
		return pycFormat{12, 5, 8, 1}, true
	case magic >= 3380 && magic <= 3399:
		return pycFormat{16, 5, 8, 1}, true
	case magic >= 3400 && magic <= 3494:
		return pycFormat{16, 6, 8, 1}, true
	case magic >= 3495 && magic <= 3700:
		return pycFormat{16, 5, 8, 2}, true
	}
	return pycFormat{}, false
}

// looksLikePyc checks the magic, the \r\n suffix, and that the marshalled
// top-level object is a code object.
func looksLikePyc(prefix []byte) bool {
	if len(prefix) < 9 || prefix[2] != '\r' || prefix[3] != '\n' {
		return false
	}
	format, ok := pycVersion(binary.LittleEndian.Uint16(prefix))
	if !ok || len(prefix) <= format.header {
		return false
	}
	return prefix[format.header]&^0x80 == 'c'
}

const (
	pycMaxDepth      = 256
	pycMaxCollection = 1 << 20
)

type pycWork struct {
	op    byte // 'o' objects, 'd' dict, 's' skip
	count uint32
	depth int
}

func extractPyc(data []byte, out *textBuffer) error {
	if !looksLikePyc(data) {
		return errors.New("not a supported .pyc file")
	}
	format, _ := pycVersion(binary.LittleEndian.Uint16(data))
	r := &pycReader{data: data[format.header:]}
	work := []pycWork{{op: 'o', count: 1}}
	first := true
	emit := func(b []byte) bool {
		if len(b) == 0 {
			return true
		}
		if !first && !out.writeByte('\n') {
			return false
		}
		first = false
		return out.write(b)
	}
	for len(work) > 0 {
		w := work[len(work)-1]
		work = work[:len(work)-1]
		switch w.op {
		case 's':
			if err := r.skip(int(w.count)); err != nil {
				return err
			}
			continue
		case 'd':
			t, err := r.u8()
			if err != nil {
				return err
			}
			if t == '0' {
				continue
			}
			r.pos--
			work = append(work, pycWork{op: 'd', depth: w.depth}, pycWork{op: 'o', count: 2, depth: w.depth})
			continue
		}
		if w.count == 0 {
			continue
		}
		if w.depth > pycMaxDepth {
			return errors.New("marshal nesting too deep")
		}
		work = append(work, pycWork{op: 'o', count: w.count - 1, depth: w.depth})
		depth := w.depth + 1
		raw, err := r.u8()
		if err != nil {
			return err
		}
		switch t := raw &^ 0x80; t {
		case '0', 'N', 'S', '.', 'T', 'F':
		case 'i', 'r':
			err = r.skip(4)
		case 'I', 'g':
			err = r.skip(8)
		case 'y':
			err = r.skip(16)
		case 'f':
			var n byte
			if n, err = r.u8(); err == nil {
				err = r.skip(int(n))
			}
		case 'x':
			for range 2 {
				var n byte
				if n, err = r.u8(); err == nil {
					err = r.skip(int(n))
				}
				if err != nil {
					break
				}
			}
		case 'l':
			var n uint32
			if n, err = r.u32(); err == nil {
				words := int64(int32(n))
				if words < 0 {
					words = -words
				}
				if words > pycMaxCollection {
					return errors.New("marshal long too large")
				}
				err = r.skip(int(words) * 2)
			}
		case 's', 't', 'u', 'a', 'A':
			var n uint32
			var b []byte
			if n, err = r.u32(); err == nil {
				if b, err = r.bytes(int(n)); err == nil && !emit(b) {
					return nil
				}
			}
		case 'z', 'Z':
			var n byte
			var b []byte
			if n, err = r.u8(); err == nil {
				if b, err = r.bytes(int(n)); err == nil && !emit(b) {
					return nil
				}
			}
		case '(', '[', '<', '>':
			var n uint32
			if n, err = r.u32(); err == nil {
				if n > pycMaxCollection {
					return errors.New("marshal collection too large")
				}
				work = append(work, pycWork{op: 'o', count: n, depth: depth})
			}
		case ')':
			var n byte
			if n, err = r.u8(); err == nil {
				work = append(work, pycWork{op: 'o', count: uint32(n), depth: depth})
			}
		case '{':
			work = append(work, pycWork{op: 'd', depth: depth})
		case ':':
			work = append(work, pycWork{op: 'o', count: 3, depth: depth})
		case 'c':
			if err = r.skip(4 * format.leadingLongs); err == nil {
				work = append(work,
					pycWork{op: 'o', count: uint32(format.trailingObjects), depth: depth},
					pycWork{op: 's', count: 4},
					pycWork{op: 'o', count: uint32(format.middleObjects), depth: depth})
			}
		default:
			return fmt.Errorf("unknown marshal type 0x%02x", t)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type pycReader struct {
	data []byte
	pos  int
}

var errPycEOF = errors.New("unexpected end of marshal data")

func (r *pycReader) bytes(n int) ([]byte, error) {
	if n < 0 || n > len(r.data)-r.pos {
		return nil, errPycEOF
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *pycReader) skip(n int) error { _, err := r.bytes(n); return err }

func (r *pycReader) u8() (byte, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *pycReader) u32() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}
