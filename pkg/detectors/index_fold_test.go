package detectors

import (
	"bytes"
	"math/rand"
	"testing"
)

// indexFoldASCIIPosRef is indexFoldASCIIPos before #1046.
func indexFoldASCIIPosRef(b, lit []byte) int {
	c0 := lit[0]
	u0 := c0
	if 'a' <= c0 && c0 <= 'z' {
		u0 = c0 - 'a' + 'A'
	}
	last := len(b) - len(lit) + 1
	for i := 0; i < last; i++ {
		j := bytes.IndexByte(b[i:last], c0)
		if u0 != c0 {
			if k := bytes.IndexByte(b[i:last], u0); k >= 0 && (j < 0 || k < j) {
				j = k
			}
		}
		if j < 0 {
			return -1
		}
		i += j
		if equalFoldASCII(b[i+1:i+len(lit)], lit[1:]) {
			return i
		}
	}
	return -1
}

// indexFoldASCIIRef is indexFoldASCII before #1046: it reports whether lower-case ASCII lit occurs in b,
// ignoring ASCII case.
func indexFoldASCIIRef(b, lit []byte) bool {
	if len(lit) == 0 {
		return true
	}
	if len(b) < len(lit) {
		return false
	}
	c0 := lit[0]
	u0 := c0
	if 'a' <= c0 && c0 <= 'z' {
		u0 = c0 - 'a' + 'A'
	}
	hay := b[:len(b)-len(lit)+1]
	// nextL/nextU cache the next occurrence of each case of the first
	// byte so every byte is searched at most once per case.
	nextL, nextU := -2, -2
	if u0 == c0 {
		nextU = -1
	}
	for i := 0; i < len(hay); {
		if nextL != -1 && nextL < i {
			if j := bytes.IndexByte(hay[i:], c0); j >= 0 {
				nextL = i + j
			} else {
				nextL = -1
			}
		}
		if nextU != -1 && nextU < i {
			if j := bytes.IndexByte(hay[i:], u0); j >= 0 {
				nextU = i + j
			} else {
				nextU = -1
			}
		}
		k := nextL
		if k < 0 || (nextU >= 0 && nextU < k) {
			k = nextU
		}
		if k < 0 {
			return false
		}
		if equalFoldASCII(b[k+1:k+len(lit)], lit[1:]) {
			return true
		}
		i = k + 1
	}
	return false
}

func TestIndexFoldASCIIPosMatchesReference(t *testing.T) {
	r := rand.New(rand.NewSource(1046))
	alphabet := []byte("aAbBkKwWsS_1-.\n")
	lits := [][]byte{[]byte("a"), []byte("ab"), []byte("abk"), []byte("_a"), []byte("1-"), []byte("kab_"), []byte("b"), []byte("swab"), []byte("asw"), []byte("Ab"), []byte("aB"), []byte("w"), []byte("s.w"), []byte("ss")}
	for i := range 200000 {
		b := make([]byte, r.Intn(40))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		lit := lits[r.Intn(len(lits))]
		got, want := indexFoldASCIIPos(b, lit), indexFoldASCIIPosRef(b, lit)
		if got != want {
			t.Fatalf("case %d: indexFoldASCIIPos(%q, %q) = %d, want %d", i, b, lit, got, want)
		}
		if gotB, wantB := indexFoldASCII(b, lit), indexFoldASCIIRef(b, lit); gotB != wantB {
			t.Fatalf("case %d: indexFoldASCII(%q, %q) = %v, want %v", i, b, lit, gotB, wantB)
		}
		if bytes.Equal(lit, bytes.ToLower(lit)) {
			if naive := bytes.Index(bytes.ToLower(b), lit); naive != want {
				t.Fatalf("case %d: reference %d, naive %d for %q %q", i, want, naive, b, lit)
			}
		}
	}
}
