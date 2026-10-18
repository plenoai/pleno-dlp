package cmd

import (
	"strings"
	"testing"
)

// TestProtectUsesSharedTransform pins that protect scans only added
// lines through the shared stagedDiffForScan transform (detailed cases
// live in hooks_git_test.go).
func TestProtectUsesSharedTransform(t *testing.T) {
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
	buf, _ := stagedDiffForScan([]byte(diff))
	got := string(buf)
	if !strings.Contains(got, "\naws_access_key=AKIA1234567890ABCDEF\n") {
		t.Errorf("added line missing from result:\n%s", got)
	}
	for _, leak := range []string{"old_key=", "AKIAIOSFODNN7EXAMPLE", "context line", "--- a/", "@@"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q leaked into result:\n%s", leak, got)
		}
	}
}

func TestProtectHelp(t *testing.T) {
	resetCommandFlags(t)

	var buf strings.Builder
	Root.SetOut(&buf)
	Root.SetErr(&buf)
	Root.SetArgs([]string{"protect", "--help"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("protect --help: %v", err)
	}
	got := buf.String()
	for _, want := range []string{"--staged", "--format", "--fail-on"} {
		if !strings.Contains(got, want) {
			t.Errorf("protect help missing %q:\n%s", want, got)
		}
	}
}
