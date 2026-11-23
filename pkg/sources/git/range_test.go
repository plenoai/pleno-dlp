package git

import (
	"sort"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// c1 ── c2 ── c3 ── M
//
//	└── s1 ──────┘   (s1 forks from c1, merges after c3)
func buildRangeRepo(t *testing.T) (dir string, h map[string]string) {
	t.Helper()
	dir = t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	h = map[string]string{}
	h["c1"] = commitOn(t, repo, map[string]string{"c1.txt": "one"}, "c1", base)
	h["s1"] = commitOnTemporaryBranch(t, repo, "side", "s1.txt", "side", base.Add(time.Minute)).String()
	h["c2"] = commitOn(t, repo, map[string]string{"c2.txt": "two"}, "c2", base.Add(2*time.Minute))
	h["c3"] = commitOn(t, repo, map[string]string{"c3.txt": "three"}, "c3", base.Add(3*time.Minute))
	h["M"] = commitMerge(t, repo, map[string]string{"s1.txt": "side"}, "merge", base.Add(4*time.Minute),
		plumbing.NewHash(h["c3"]), plumbing.NewHash(h["s1"]))
	return dir, h
}

func rangeCommits(t *testing.T, cfg Config) []string {
	t.Helper()
	s := &Source{}
	mustInit(t, s, cfg)
	chunks, err := drain(t, s, 20*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if s.IncrementalState() != nil {
		t.Errorf("ranged scan must not publish a fresh checkpoint")
	}
	set := map[string]bool{}
	for _, c := range chunks {
		set[c.SourceMetadata.Git.Commit] = true
	}
	var out []string
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func names(h map[string]string, keys ...string) []string {
	var out []string
	for _, k := range keys {
		out = append(out, h[k])
	}
	sort.Strings(out)
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRangeScan(t *testing.T) {
	dir, h := buildRangeRepo(t)
	cases := []struct {
		name string
		cfg  Config
		want []string
	}{
		// s1 is older than c2 but outside its ancestry, so it is in range.
		{"since c2", Config{Repo: dir, SinceCommit: h["c2"]}, names(h, "c3", "s1")},
		{"since HEAD~1", Config{Repo: dir, SinceCommit: "HEAD~1"}, names(h, "s1")},
		{"branch root c2", Config{Repo: dir, BranchRootCommit: h["c2"]}, names(h, "c2", "c3", "s1")},
		{"branch root c1 (root commit)", Config{Repo: dir, BranchRootCommit: h["c1"]}, names(h, "c1", "c2", "c3", "s1")},
	}
	run := func(t *testing.T) {
		for _, tc := range cases {
			// Merge chunks may add M; it is in range for every case here.
			got := rangeCommits(t, tc.cfg)
			want := append(append([]string(nil), tc.want...), h["M"])
			sort.Strings(want)
			if !equal(got, tc.want) && !equal(got, want) {
				t.Errorf("%s: got %v want %v (+M)", tc.name, got, tc.want)
			}
		}
	}
	t.Run("native", run)
	t.Run("go-git", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		run(t)
	})
}

func TestRangeScanErrors(t *testing.T) {
	dir, h := buildRangeRepo(t)
	s := &Source{}
	mustInit(t, s, Config{Repo: dir, SinceCommit: "does-not-exist"})
	if _, err := drain(t, s, 10*time.Second); err == nil {
		t.Fatal("unresolvable revision must fail, not fall back to full history")
	}
	for _, cfg := range []Config{
		{Repo: dir, SinceCommit: h["c1"], BranchRootCommit: h["c2"]},
		{Repo: dir, SinceCommit: "--output=/tmp/x"},
	} {
		raw := []byte(`{"repo":"` + cfg.Repo + `","since_commit":"` + cfg.SinceCommit + `","branch_root_commit":"` + cfg.BranchRootCommit + `"}`)
		if err := (&Source{}).Init(t.Context(), "t", 1, 1, false, raw, 1); err == nil {
			t.Errorf("Init(%+v) must fail", cfg)
		}
	}
}
