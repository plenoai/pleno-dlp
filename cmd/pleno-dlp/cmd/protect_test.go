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

// TestStagedDiffForScan_ScansDoublePlusAddedLines pins the self-heal for
// #489: inside a hunk, an added line whose content itself begins with
// "++" renders as "+++..." and must still be scanned, while a real
// "+++ b/<path>" file header is only recognized outside a hunk.
func TestStagedDiffForScan_ScansDoublePlusAddedLines(t *testing.T) {
	diff := "diff --git a/a.txt b/a.txt\n" +
		"new file mode 100644\n" +
		"index 0000000..abc1234\n" +
		"--- /dev/null\n" +
		"+++ b/a.txt\n" +
		"@@ -0,0 +1,3 @@\n" +
		"+++ b/secret.txt\n" +
		"+++ token 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\n" +
		"+ordinary added line\n"
	buf, origins := stagedDiffForScan([]byte(diff))
	got := string(buf)
	// Content added inside the hunk must survive even though its rendered
	// form is indistinguishable from a file header by prefix alone.
	for _, want := range []string{
		"++ b/secret.txt\n",
		"++ token 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\n",
		"ordinary added line\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("added content %q missing from result:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "+++ b/"); n != 1 {
		t.Errorf("want exactly one '+++ b/' header, got %d:\n%s", n, got)
	}
	wantOrigins := []diffOrigin{{"a.txt", 0}, {"a.txt", 1}, {"a.txt", 2}, {"a.txt", 3}}
	if len(origins) != len(wantOrigins) {
		t.Fatalf("origins = %v, want %v", origins, wantOrigins)
	}
	for i := range wantOrigins {
		if origins[i] != wantOrigins[i] {
			t.Errorf("origins[%d] = %v, want %v", i, origins[i], wantOrigins[i])
		}
	}
}

// TestStagedDiffForScan_DropsDoubleMinusRemovedLines pins that a removed
// line whose content begins with "--" (rendered "---...") is not scanned,
// even though it looks like an old-file header by prefix.
func TestStagedDiffForScan_DropsDoubleMinusRemovedLines(t *testing.T) {
	diff := "diff --git a/a.txt b/a.txt\n" +
		"index abc1234..def5678 100644\n" +
		"--- a/a.txt\n" +
		"+++ b/a.txt\n" +
		"@@ -1,2 +1,1 @@\n" +
		"--- old token ghp_removed\n" +
		"+new content\n"
	buf, _ := stagedDiffForScan([]byte(diff))
	got := string(buf)
	if strings.Contains(got, "old token") || strings.Contains(got, "ghp_removed") {
		t.Errorf("removed content leaked into result:\n%s", got)
	}
	if !strings.Contains(got, "new content\n") {
		t.Errorf("added line missing from result:\n%s", got)
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

// TestStagedDiffForScan_NoNewlineMarker pins that the "\ No newline at end
// of file" marker is dropped while the added line before it is scanned.
func TestStagedDiffForScan_NoNewlineMarker(t *testing.T) {
	diff := "diff --git a/a.txt b/a.txt\n" +
		"index abc1234..def5678 100644\n" +
		"--- a/a.txt\n" +
		"+++ b/a.txt\n" +
		"@@ -1 +1 @@\n" +
		"+secret AKIA1234567890ABCDEF\n" +
		"\\ No newline at end of file\n"
	buf, _ := stagedDiffForScan([]byte(diff))
	got := string(buf)
	if !strings.Contains(got, "secret AKIA1234567890ABCDEF\n") {
		t.Errorf("added line missing from result:\n%s", got)
	}
	if strings.Contains(got, "No newline") {
		t.Errorf("no-newline marker leaked into result:\n%s", got)
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

// TestStagedDiffForScan_MultipleFiles pins that hunk state resets at each
// new file section so no header is mistaken for content across files.
func TestStagedDiffForScan_MultipleFiles(t *testing.T) {
	diff := "diff --git a/a.txt b/a.txt\n" +
		"--- a/a.txt\n" +
		"+++ b/a.txt\n" +
		"@@ -1 +1 @@\n" +
		"+first added\n" +
		"diff --git a/b.txt b/b.txt\n" +
		"--- a/b.txt\n" +
		"+++ b/b.txt\n" +
		"@@ -1 +1 @@\n" +
		"+second added\n"
	buf, _ := stagedDiffForScan([]byte(diff))
	got := string(buf)
	if !strings.Contains(got, "first added\n") || !strings.Contains(got, "second added\n") {
		t.Errorf("added lines missing from result:\n%s", got)
	}
	if n := strings.Count(got, "+++ b/"); n != 2 {
		t.Errorf("want two '+++ b/' headers, got %d:\n%s", n, got)
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
