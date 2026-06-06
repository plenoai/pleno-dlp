package cmd

import (
	"strings"
	"testing"
)

// TestExtractAddedLines verifies the core diff-filtering logic:
// only '+'-prefixed lines (minus the '+++' file header) should
// reach the scanner. Removed lines and context lines must be
// dropped so pre-commit never fires on secrets being deleted.
func TestExtractAddedLines(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
index abc..def 100644
--- a/config.go
+++ b/config.go
@@ -1,3 +1,4 @@
 package main
+aws_access_key=AKIA1234567890ABCDEF
-old_key=AKIAIOSFODNN7EXAMPLE
 // context line
`

	got := extractAddedLines(diff)

	// Added line must be present (without the leading '+').
	if !strings.Contains(got, "aws_access_key=AKIA1234567890ABCDEF") {
		t.Errorf("added line missing from result:\n%s", got)
	}

	// Removed line must not appear.
	if strings.Contains(got, "old_key=") || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("removed line leaked into result:\n%s", got)
	}

	// Context line must not appear.
	if strings.Contains(got, "context line") {
		t.Errorf("context line leaked into result:\n%s", got)
	}

	// '+++' file header must not appear.
	if strings.Contains(got, "+++") {
		t.Errorf("diff header leaked into result:\n%s", got)
	}
}

func TestExtractAddedLines_EmptyDiff(t *testing.T) {
	if got := extractAddedLines(""); got != "" {
		t.Errorf("empty diff should return empty string, got %q", got)
	}
}

func TestExtractAddedLines_NoAdditions(t *testing.T) {
	diff := `diff --git a/foo.go b/foo.go
--- a/foo.go
+++ b/foo.go
@@ -1,2 +1,1 @@
 unchanged
-removed line
`
	if got := extractAddedLines(diff); got != "" {
		t.Errorf("diff with no additions should return empty string, got %q", got)
	}
}

func TestProtectHelp(t *testing.T) {
	var buf strings.Builder
	Root.SetOut(&buf)
	Root.SetErr(&buf)
	Root.SetArgs([]string{"protect", "--help"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("protect --help: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"--staged", "--format", "--verify", "--fail-on"} {
		if !strings.Contains(got, want) {
			t.Errorf("protect help missing %q:\n%s", want, got)
		}
	}
}
