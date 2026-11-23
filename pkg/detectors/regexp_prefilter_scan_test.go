package detectors

import (
	"math/rand"
	"testing"
	"unicode/utf8"
)

func naiveRunPresent(r *byteRun, b []byte) bool {
	n := 0
	for _, c := range b {
		if r.class[c] {
			n++
			if n >= r.min {
				return true
			}
		} else {
			n = 0
		}
	}
	return false
}

// TestByteRunPresentMatchesLinearScan pins the strided run search to the
// byte-by-byte definition over random class densities and run lengths.
func TestByteRunPresentMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 20000; iter++ {
		var r byteRun
		r.min = rng.Intn(24)
		for c := 'a'; c <= 'f'; c++ {
			r.class[c] = true
		}
		density := rng.Float64()
		b := make([]byte, rng.Intn(200))
		for i := range b {
			if rng.Float64() < density {
				b[i] = byte('a' + rng.Intn(6))
			} else {
				b[i] = byte('g' + rng.Intn(6))
			}
		}
		if got, want := r.present(b), naiveRunPresent(&r, b); got != want {
			t.Fatalf("min=%d b=%q: present=%v want %v", r.min, b, got, want)
		}
	}
}

func TestHasNonASCIIMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for iter := 0; iter < 20000; iter++ {
		b := make([]byte, rng.Intn(100))
		for i := range b {
			b[i] = byte(rng.Intn(128))
		}
		want := false
		if len(b) > 0 && rng.Intn(2) == 0 {
			b[rng.Intn(len(b))] = byte(128 + rng.Intn(128))
			want = true
		}
		for _, c := range b {
			if c >= utf8.RuneSelf {
				want = true
			}
		}
		if got := hasNonASCII(b); got != want {
			t.Fatalf("%q: got %v want %v", b, got, want)
		}
	}
}
