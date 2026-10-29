package stdin

import (
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestParseDiff_MapsAddedLinesToFiles(t *testing.T) {
	diff := "diff --git a/config.go b/config.go\n" +
		"index abc..def 100644\n" +
		"--- a/config.go\n" +
		"+++ b/config.go\n" +
		"@@ -1,3 +1,4 @@\n" +
		" package main\n" +
		"+aws_access_key=AKIA1234567890ABCDEF\n" +
		"-old_key=AKIAIOSFODNN7EXAMPLE\n" +
		" // context line\n" +
		"diff --git a/sub/second.go b/sub/second.go\n" +
		"--- a/sub/second.go\n" +
		"+++ b/sub/second.go\n" +
		"@@ -10,2 +10,2 @@\n" +
		" keep\n" +
		"+secret=SECOND\n"
	buf, locs := ParseDiff([]byte(diff))
	want := "+++ b/config.go\naws_access_key=AKIA1234567890ABCDEF\n+++ b/sub/second.go\nsecret=SECOND\n"
	if string(buf) != want {
		t.Fatalf("buffer mismatch:\n got %q\nwant %q", buf, want)
	}
	m := LocationMap(locs)
	if got := m[2]; got != (sources.LineLocation{Path: "config.go", Line: 2}) {
		t.Errorf("line 2 = %+v, want {config.go 2}", got)
	}
	if got := m[4]; got != (sources.LineLocation{Path: "sub/second.go", Line: 11}) {
		t.Errorf("line 4 = %+v, want {sub/second.go 11}", got)
	}
	if got := m[1]; got != (sources.LineLocation{Path: "config.go"}) {
		t.Errorf("header line 1 = %+v, want {config.go 0}", got)
	}
}

func TestParseDiff_NoAdditions(t *testing.T) {
	if buf, locs := ParseDiff(nil); buf != nil || locs != nil {
		t.Errorf("empty diff: got %q, %v", buf, locs)
	}
	diff := "diff --git a/foo.go b/foo.go\n--- a/foo.go\n+++ b/foo.go\n@@ -1,2 +1,1 @@\n unchanged\n-removed line\n"
	if buf, locs := ParseDiff([]byte(diff)); buf != nil || locs != nil {
		t.Errorf("diff with no additions: got %q, %v", buf, locs)
	}
}

func TestDiffFilePath(t *testing.T) {
	cases := map[string]string{
		`"b/a b.go"` + "\t2026-10-30 00:00:00 +0000": "a b.go",
		`"b/a\"b.go"` + "\tstamp":                    `a"b.go`,
		`"b/tab\tname.go"` + "\tstamp":               "tab\tname.go",
		"b/config.go":                                "config.go",
		"b/sub/dir/file.go\tstamp":                   "sub/dir/file.go",
		`"b/a b/c.go"`:                               "a b/c.go",
		`"b/tab\tname.go"`:                           "tab\tname.go",
		"/dev/null":                                  "",
		"":                                           "",
	}
	for in, want := range cases {
		if got := diffFilePath(in); got != want {
			t.Errorf("diffFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
