package catalog

import (
	"math/rand"
	"testing"
)

func naiveHexRunBeforeDot(n int, data []byte) bool {
	run := 0
	for _, c := range data {
		switch {
		case isHexDigit(c):
			run++
		case c == '.' && run >= n:
			return true
		default:
			run = 0
		}
	}
	return false
}

// TestHexRunBeforeDotMatchesLinearScan pins the dot-anchored search to the
// byte-by-byte run definition.
func TestHexRunBeforeDotMatchesLinearScan(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	alphabet := []byte("0aF..g x")
	for iter := 0; iter < 20000; iter++ {
		n := rng.Intn(6)
		b := make([]byte, rng.Intn(40))
		for i := range b {
			if rng.Intn(3) > 0 {
				b[i] = alphabet[rng.Intn(3)]
			} else {
				b[i] = alphabet[rng.Intn(len(alphabet))]
			}
		}
		if got, want := hexRunBeforeDot(n)(b), naiveHexRunBeforeDot(n, b); got != want {
			t.Fatalf("n=%d %q: got %v want %v", n, b, got, want)
		}
	}
}
