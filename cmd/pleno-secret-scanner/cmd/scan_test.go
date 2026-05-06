package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestScanHelp confirms the scan subcommand is wired into Root and renders
// help with the expected flags. Real e2e coverage (with a fixture filesystem
// and a stub source) is qa's job — this test only guards the wiring.
func TestScanHelp(t *testing.T) {
	var out bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&out)
	Root.SetArgs([]string{"scan", "--help"})

	if err := Root.Execute(); err != nil {
		t.Fatalf("scan --help: %v", err)
	}

	got := out.String()
	for _, want := range []string{"--format", "--verify", "--concurrency", "scan"} {
		if !strings.Contains(got, want) {
			t.Errorf("help missing %q in:\n%s", want, got)
		}
	}
}

func TestScanRequiresPath(t *testing.T) {
	// Args validation runs before RunE, so we can drive it without exercising
	// the source registry. Using cobra.Command.Args directly avoids state
	// bleed from sibling tests that may have flipped help flags on Root.
	if err := scanCmd.Args(scanCmd, []string{}); err == nil {
		t.Errorf("expected error when no path given")
	}
}

func TestIsFindingsError(t *testing.T) {
	if !IsFindingsError(errFindingsFound) {
		t.Errorf("sentinel must match itself")
	}
	if IsFindingsError(nil) {
		t.Errorf("nil must not match")
	}
}
