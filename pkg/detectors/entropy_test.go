package detectors

import (
	"math"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Fatalf("expected 0 for empty, got %v", got)
	}
}

func TestShannonEntropy_SingleChar(t *testing.T) {
	// All-identical input → 0 bits of entropy.
	if got := ShannonEntropy("aaaaaaaa"); got != 0 {
		t.Fatalf("expected 0 for all-same, got %v", got)
	}
}

func TestShannonEntropy_Zeros(t *testing.T) {
	if got := ShannonEntropy("00000000000000000000000000000000"); got != 0 {
		t.Fatalf("expected 0 for all-zeros, got %v", got)
	}
}

func TestShannonEntropy_RepeatedPair(t *testing.T) {
	// "abababab..." alternates 2 symbols → 1.0 bits/char.
	got := ShannonEntropy("abababababababab")
	if math.Abs(got-1.0) > 1e-9 {
		t.Fatalf("expected ~1.0 for ababab, got %v", got)
	}
}

func TestShannonEntropy_RandomHex(t *testing.T) {
	// A real-looking hex string should clear 3.0 bits/char (16
	// symbol alphabet → ceiling 4.0).
	tok := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got := ShannonEntropy(tok); got < 3.5 {
		t.Fatalf("expected >=3.5 for diverse hex, got %v", got)
	}
}

func TestHasMinEntropy(t *testing.T) {
	if HasMinEntropy("00000000000000000000000000000000", 1.0) {
		t.Fatal("zeros should not meet threshold 1.0")
	}
	if !HasMinEntropy("9f86d081884c7d659a2feaa0c55ad015", 3.0) {
		t.Fatal("real hex should meet threshold 3.0")
	}
}
