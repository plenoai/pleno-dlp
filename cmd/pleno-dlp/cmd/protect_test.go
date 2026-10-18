package cmd

import (
	"bytes"
	"os"
	"path/filepath"
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

func TestCollectDiffForScan_LineToPathMapping(t *testing.T) {
	diff := "diff --git a/fixtures/leak.env b/fixtures/leak.env\n" +
		"--- a/fixtures/leak.env\n" +
		"+++ b/fixtures/leak.env\n" +
		"@@ -1,1 +1,2 @@\n" +
		" context\n" +
		"+token=FIXTURE_ABCDEFGHIJKLMNOPQR\n"
	added, locations := collectDiffForScan(diff)
	if added != "token=FIXTURE_ABCDEFGHIJKLMNOPQR\n" {
		t.Fatalf("added = %q", added)
	}
	loc, ok := locations[1]
	if !ok {
		t.Fatalf("no location for added line 1: %v", locations)
	}
	if loc != "fixtures/leak.env:2" {
		t.Fatalf("location = %q, want %q", loc, "fixtures/leak.env:2")
	}
}

// TestProtect_AllowlistPathMatchesDiffFinding is the end-to-end regression
// for the bug this change fixes: a .pleno-allow.json `path` entry must match
// a finding produced by `protect`, whose diff arrives through the stdin
// source. Before the fix, findingPath returned the opaque "git-diff-staged"
// label and the path rule never matched.
func TestProtect_AllowlistPathMatchesDiffFinding(t *testing.T) {
	resetCommandFlags(t)
	dir := t.TempDir()
	t.Chdir(dir)
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "test")
	if err := os.MkdirAll(filepath.Join(dir, "fixtures"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixtures", "leak.env"), []byte("token=FIXTURE_ABCDEFGHIJKLMNOPQR\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, dir, "add", "fixtures/leak.env")

	tmp := t.TempDir()
	rules := filepath.Join(tmp, "rules.json")
	if err := writeFile(rules, `[{"name":"Fixture Token","keywords":["FIXTURE_"],"regex":"FIXTURE_[A-Z]{20}","severity":"high"}]`); err != nil {
		t.Fatal(err)
	}
	allow := filepath.Join(tmp, ".pleno-allow.json")
	if err := writeFile(allow, `{"entries":[{"path":"fixtures/**","reason":"checked-in fixture"}]}`); err != nil {
		t.Fatal(err)
	}

	var out, errBuf bytes.Buffer
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"protect", "--rules", rules, "--format", "json"})
	if err := Root.Execute(); !IsFindingsError(err) {
		t.Fatalf("without an allowlist protect should gate on the finding; got %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "fixtures/leak.env") {
		t.Fatalf("finding should report the real path, not git-diff-staged:\n%s", out.String())
	}

	resetCommandFlagsNow()
	out.Reset()
	errBuf.Reset()
	Root.SetOut(&out)
	Root.SetErr(&errBuf)
	Root.SetArgs([]string{"protect", "--rules", rules, "--allowlist", allow, "--format", "json"})
	if err := Root.Execute(); err != nil {
		t.Fatalf("allowlisted finding must exit 0; got %v\nstdout:\n%s\nstderr:\n%s", err, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "allowlist: suppressed") {
		t.Errorf("expected an allowlist suppression signal on stderr; got:\n%s", errBuf.String())
	}
	if strings.Contains(out.String(), "fixtures/leak.env") {
		t.Errorf("allowlisted finding should not be emitted:\n%s", out.String())
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
