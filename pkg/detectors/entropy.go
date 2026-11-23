// Shannon entropy helpers shared by provider-specific detectors.
package detectors

import "math"

// ShannonEntropy returns the Shannon entropy of s in bits per byte.
//
// Byte frequencies live in a stack array and are summed in byte order: the
// previous map-based version allocated per call (0.59 CPU-s of the generic
// detector on django git history, #1020) and summed in random map order, so
// the last float bit could differ between runs of the same input.
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

func HasMinEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) >= threshold
}
