package stdin

import (
	"strings"
	"testing"
)

func TestCollectDiffForScan_MapsAddedLinesToFiles(t *testing.T) {
	diff := `diff --git a/config.go b/config.go
index abc..def 100644
--- a/config.go
+++ b/config.go
@@ -1,3 +1,4 @@
 package main
+aws_access_key=AKIA1234567890ABCDEF
-old_key=AKIAIOSFODNN7EXAMPLE
 // context line
diff --git a/sub/second.go b/sub/second.go
--- a/sub/second.go
+++ b/sub/second.go
@@ -10,2 +10,2 @@
 keep
+secret=SECOND
`
	got, locations := CollectDiffForScan([]byte(diff))
	want := "aws_access_key=AKIA1234567890ABCDEF\nsecret=SECOND\n"
	if string(got) != want {
		t.Fatalf("added lines mismatch:\n got %q\nwant %q", got, want)
	}
	if strings.Contains(string(got), "old_key") || strings.Contains(string(got), "context line") {
		t.Fatalf("removed/context content leaked into scan data: %q", got)
	}

	first, ok := locations[1]
	if !ok {
		t.Fatalf("no location for added line 1: %v", locations)
	}
	if first.Path != "config.go" || first.Line != 2 {
		t.Errorf("line 1 location = %+v, want {config.go 2}", first)
	}
	second, ok := locations[2]
	if !ok {
		t.Fatalf("no location for added line 2: %v", locations)
	}
	if second.Path != "sub/second.go" || second.Line != 11 {
		t.Errorf("line 2 location = %+v, want {sub/second.go 11}", second)
	}
	if len(locations) != 2 {
		t.Errorf("want 2 locations, got %d: %v", len(locations), locations)
	}
}

func TestCollectDiffForScan_EmptyAndNoAdditions(t *testing.T) {
	if got, loc := CollectDiffForScan(nil); string(got) != "" || len(loc) != 0 {
		t.Errorf("empty diff: got %q, %v", got, loc)
	}
	diff := `diff --git a/foo.go b/foo.go
--- a/foo.go
+++ b/foo.go
@@ -1,2 +1,1 @@
 unchanged
-removed line
`
	if got, loc := CollectDiffForScan([]byte(diff)); string(got) != "" || len(loc) != 0 {
		t.Errorf("diff with no additions: got %q, %v", got, loc)
	}
}

func TestDiffFilePath(t *testing.T) {
	cases := map[string]string{
		"b/config.go\n":              "config.go",
		"b/sub/dir/file.go\tstamp":   "sub/dir/file.go",
		`"b/a b/c.go"`:               "a b/c.go",
		`"b/tab\tname.go"`:           "tab\tname.go",
		"a/old.go":                   "a/old.go",
		"/dev/null":                  "",
		"":                           "",
	}
	for in, want := range cases {
		if got := diffFilePath(in); got != want {
			t.Errorf("diffFilePath(%q) = %q, want %q", in, got, want)
		}
	}
}
