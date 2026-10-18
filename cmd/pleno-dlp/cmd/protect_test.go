package cmd

import (
	"strings"
	"testing"
)

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

	if !strings.Contains(got, "aws_access_key=AKIA1234567890ABCDEF") {
		t.Errorf("added line missing from result:\n%s", got)
	}

	if strings.Contains(got, "old_key=") || strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("removed line leaked into result:\n%s", got)
	}

	if strings.Contains(got, "context line") {
		t.Errorf("context line leaked into result:\n%s", got)
	}

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

func TestExtractAddedLines_DoublePlusContent(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
new file mode 100644
index 0000000..abc1234
--- /dev/null
+++ b/a.txt
@@ -0,0 +1,2 @@
+++ token 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
+ordinary added line
`

	got := extractAddedLines(diff)

	if !strings.Contains(got, "++ token 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") {
		t.Errorf("added line starting with '++' missing from result:\n%s", got)
	}
	if !strings.Contains(got, "ordinary added line") {
		t.Errorf("ordinary added line missing from result:\n%s", got)
	}
	if strings.Contains(got, "+++ b/a.txt") {
		t.Errorf("diff header leaked into result:\n%s", got)
	}
}

func TestExtractAddedLines_DoubleMinusRemovedContent(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
index abc1234..def5678 100644
--- a/a.txt
+++ b/a.txt
@@ -1,2 +1,1 @@
--- old token ghp_removed
+new content
`

	got := extractAddedLines(diff)

	if strings.Contains(got, "old token") || strings.Contains(got, "ghp_removed") {
		t.Errorf("removed line starting with '--' leaked into result:\n%s", got)
	}
	if !strings.Contains(got, "new content") {
		t.Errorf("added line missing from result:\n%s", got)
	}
}

func TestExtractAddedLines_NoNewlineMarker(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
index abc1234..def5678 100644
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
+secret AKIA1234567890ABCDEF
\ No newline at end of file
`

	got := extractAddedLines(diff)

	if got != "secret AKIA1234567890ABCDEF\n" {
		t.Errorf("unexpected result:\n%q", got)
	}
	if strings.Contains(got, "No newline") {
		t.Errorf("no-newline marker leaked into result:\n%s", got)
	}
}

func TestExtractAddedLines_MultipleFiles(t *testing.T) {
	diff := `diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1 +1 @@
+first added
diff --git a/b.txt b/b.txt
--- a/b.txt
+++ b/b.txt
@@ -1 +1 @@
+second added
`

	got := extractAddedLines(diff)

	if !strings.Contains(got, "first added") || !strings.Contains(got, "second added") {
		t.Errorf("added lines missing from result:\n%s", got)
	}
	if strings.Contains(got, "+++ b/") {
		t.Errorf("diff header leaked into result:\n%s", got)
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
