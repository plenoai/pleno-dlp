package expo

import (
	"math/rand"
	"strings"
	"testing"
)

// TestMayHaveKeywordIsNecessary pins that the byte prefilter never rejects
// input keywordRe matches.
func TestMayHaveKeywordIsNecessary(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	pieces := []string{"expo", "EXPO", "Eas", "eAS", "_", "-", ".", " ", "\t", "token", "access", "pat", "dev", "x", "please", "ſ", "eaſ", "\n", "e"}
	matched := 0
	for i := 0; i < 50000; i++ {
		var b strings.Builder
		for j := 0; j < rng.Intn(10); j++ {
			b.WriteString(pieces[rng.Intn(len(pieces))])
		}
		data := []byte(b.String())
		if keywordRe().Match(data) {
			matched++
			if !mayHaveKeyword(data) {
				t.Fatalf("prefilter rejected matching input %q", data)
			}
		}
	}
	if matched == 0 {
		t.Fatal("no matching inputs generated")
	}
}
