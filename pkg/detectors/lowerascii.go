package detectors

import "encoding/binary"

// LowerASCIIInto writes src with ASCII 'A'-'Z' mapped to lower case into
// dst (grown when too small) and returns it; every other byte, including
// non-ASCII ones, is copied unchanged. Eight bytes are folded per step.
func LowerASCIIInto(dst, src []byte) []byte {
	if cap(dst) < len(src) {
		dst = make([]byte, len(src))
	} else {
		dst = dst[:len(src)]
	}
	const (
		low7 = 0x7f7f7f7f7f7f7f7f
		hi   = 0x8080808080808080
		geA  = 0x3f3f3f3f3f3f3f3f // 0x80 - 'A': high bit once a byte >= 'A'
		gtZ  = 0x2525252525252525 // 0x80 - 'Z' - 1: high bit once a byte > 'Z'
	)
	i := 0
	for ; i+8 <= len(src); i += 8 {
		w := binary.LittleEndian.Uint64(src[i:])
		h := w & low7
		upper := (h + geA) &^ (h + gtZ) &^ w & hi
		binary.LittleEndian.PutUint64(dst[i:], w|upper>>2)
	}
	for ; i < len(src); i++ {
		c := src[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst[i] = c
	}
	return dst
}
