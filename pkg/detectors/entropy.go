// Shannon entropy helpers shared by provider-specific detectors.
package detectors

import "math"

func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[byte]int, len(s))
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range freq {
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}

func HasMinEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) >= threshold
}
