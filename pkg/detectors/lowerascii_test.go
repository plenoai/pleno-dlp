package detectors

import "testing"

// TestLowerASCIIIntoEveryByte checks each byte value in each word lane
// against the scalar definition.
func TestLowerASCIIIntoEveryByte(t *testing.T) {
	for v := 0; v < 256; v++ {
		for lane := 0; lane < 11; lane++ {
			src := []byte("xYz@[`{AZaz0")[:11]
			src[lane] = byte(v)
			got := LowerASCIIInto(nil, src)
			for i, c := range src {
				want := c
				if 'A' <= c && c <= 'Z' {
					want = c + 'a' - 'A'
				}
				if got[i] != want {
					t.Fatalf("byte %#x lane %d pos %d: got %#x want %#x", v, lane, i, got[i], want)
				}
			}
		}
	}
}
