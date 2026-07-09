// Package main implements the dlp-bench synthetic-corpus generator (see
// bench/README.md). It exists because docs/comparison.md's §2 corpus was
// historically hand-built and never committed ("generators and raw
// outputs are not committed" — comparison.md's own Reproducing section);
// issue #298 asks for that generator to become a real, run-again asset.
//
// rand.go: deterministic charset sampling shared by every fixture in
// spec.go. A fixed default seed makes `go run ./bench/gen` reproducible
// across machines — the whole point of a public benchmark asset — while
// still exposing -seed for anyone auditing that the corpus isn't
// cherry-picked to a single lucky draw.
package main

import "math/rand/v2"

const (
	charsetLower    = "abcdefghijklmnopqrstuvwxyz"
	charsetUpper    = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	charsetDigit    = "0123456789"
	charsetHex      = "0123456789abcdef"
	charsetHexUpper = "0123456789ABCDEF"
	charsetAlnum    = charsetUpper + charsetLower + charsetDigit
	charsetUpperNum = charsetUpper + charsetDigit
	charsetURLSafe  = charsetAlnum + "-_"
	charsetBase64   = charsetAlnum + "+/"
)

// sample draws n characters from charset using rng.
func sample(rng *rand.Rand, charset string, n int) string {
	out := make([]byte, n)
	for i := range out {
		out[i] = charset[rng.IntN(len(charset))]
	}
	return string(out)
}

// newRNG builds the fixture RNG from seed. A fixed seed2 (0) is fine here:
// PCG only needs seed to differ across -seed invocations, and this
// generator never runs concurrently with itself.
func newRNG(seed uint64) *rand.Rand {
	return rand.New(rand.NewPCG(seed, 0))
}
