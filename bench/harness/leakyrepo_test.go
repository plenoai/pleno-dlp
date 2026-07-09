package main

import (
	"os"
	"path/filepath"
	"testing"
)

// sample is a trimmed, unmodified excerpt of leaky-repo's own
// .leaky-meta/secrets.csv (fetched at leakyRepoCommit while building
// this harness) — including a risk>0 row, an informative-only row, a
// comment block, and a blank line, so the parser is exercised against
// every line shape the real file contains.
const sample = `#########################################################################################################
# We break secrets into two categories, "risk" and "informative".
#########################################################################################################
# name,num_risk,num_informative
.bash_profile,6,5
.bashrc,3,3

# Here the users are informative, the auth is risk.
.docker/.dockercfg,2,2
.ssh/id_rsa,1,0
.ssh/id_rsa.pub,0,1
high-entropy-misc.txt,0,2
`

func TestParseLeakyRepoGroundTruth(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".leaky-meta"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".leaky-meta", "secrets.csv"), []byte(sample), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := parseLeakyRepoGroundTruth(dir)
	if err != nil {
		t.Fatalf("parseLeakyRepoGroundTruth: %v", err)
	}
	want := []string{
		".bash_profile", ".bashrc", ".docker/.dockercfg",
		".ssh/id_rsa", ".ssh/id_rsa.pub", "high-entropy-misc.txt",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d files, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("entry %d: got %q, want %q", i, got[i], w)
		}
	}
}

func TestParseLeakyRepoGroundTruth_MissingFile(t *testing.T) {
	if _, err := parseLeakyRepoGroundTruth(t.TempDir()); err == nil {
		t.Fatal("expected an error for a directory with no .leaky-meta/secrets.csv")
	}
}
