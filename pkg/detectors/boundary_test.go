package detectors

import (
	"strings"
	"testing"
)

func TestHasWordRunCandidate(t *testing.T) {
	classic := "ghp_" + strings.Repeat("A", 36)
	fine := "github_pat_" + strings.Repeat("A", 82)
	tests := []struct {
		name   string
		data   string
		prefix string
		length int
		want   bool
	}{
		{"classic", " " + classic, "ghp_", len(classic), true},
		{"fine with underscore", " " + fine, "github_pat_", len(fine), true},
		{"short body", " ghp_" + strings.Repeat("A", 35), "ghp_", len(classic), false},
		{"non-word body", " ghp_" + strings.Repeat("A", 35) + "!", "ghp_", len(classic), false},
		{"word prefix", "x" + classic, "ghp_", len(classic), false},
		{"unicode prefix", "é" + classic, "ghp_", len(classic), true},
		{"later complete candidate", " ghp_short " + classic, "ghp_", len(classic), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasWordRunCandidate([]byte(tc.data), tc.prefix, tc.length); got != tc.want {
				t.Fatalf("HasWordRunCandidate(%q, %q, %d) = %v, want %v", tc.data, tc.prefix, tc.length, got, tc.want)
			}
		})
	}
}
