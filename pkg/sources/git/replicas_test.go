package git

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// buildReplicaRepo re-adds identical files at the same path (a vendor tree
// removed and restored) and repeats a modification on a side branch, so the
// same (path, pre-image, post-image) diff appears in several commits.
func buildReplicaRepo(t *testing.T) string {
	dir := buildShardRepo(t)
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for round := 0; round < 3; round++ {
		write("vendor.txt", "vendored token secret-v\n")
		write("w.dat", "attribute-binary vendored secret-w\n")
		gitRun(t, dir, "add", "-A")
		gitRun(t, dir, "commit", "-qm", "vendor")
		gitRun(t, dir, "rm", "-q", "vendor.txt", "w.dat")
		gitRun(t, dir, "commit", "-qm", "unvendor")
	}
	gitRun(t, dir, "checkout", "-q", "-b", "pick")
	write("c-added.txt", "added later secret-c\nmodified secret-m\n")
	gitRun(t, dir, "commit", "-qam", "modify on pick")
	gitRun(t, dir, "checkout", "-q", "main")
	write("c-added.txt", "added later secret-c\nmodified secret-m\n")
	gitRun(t, dir, "commit", "-qam", "same modify on main")
	return dir
}

func replicaChunkKeys(t *testing.T, dir string, minCommits int, collapse bool) (keys []string, skipped int) {
	t.Helper()
	old := nativeShardMinCommits
	nativeShardMinCommits = minCommits
	defer func() { nativeShardMinCommits = old }()
	s := &Source{}
	mustInit(t, s, Config{Repo: dir, AllBranches: true, CollapseIdenticalDiffs: collapse})
	s.concurrency = 4
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	for _, c := range got {
		g := c.SourceMetadata.Git
		keys = append(keys, g.Commit+" "+g.File+" "+string(c.Data))
		if g.Replicas != nil {
			for _, r := range g.Replicas.List() {
				m := r.Apply(*g)
				keys = append(keys, m.Commit+" "+m.File+" "+string(c.Data))
				skipped++
			}
		}
	}
	sort.Strings(keys)
	return keys, skipped
}

// TestCollapseIdenticalDiffsExpandsToFullSurface pins that scanning each
// identical diff once and expanding its replicas reproduces exactly the
// per-commit chunk surface, on both the single stream and parallel shards,
// including the forced-text path for attribute-binary files.
func TestCollapseIdenticalDiffsExpandsToFullSurface(t *testing.T) {
	dir := buildReplicaRepo(t)
	for _, minCommits := range []int{1 << 30, 1} {
		want, _ := replicaChunkKeys(t, dir, minCommits, false)
		got, skipped := replicaChunkKeys(t, dir, minCommits, true)
		if strings.Join(want, "\n") != strings.Join(got, "\n") {
			t.Fatalf("minCommits=%d: expanded chunks differ\nwant:\n%s\ngot:\n%s", minCommits, strings.Join(want, "\n"), strings.Join(got, "\n"))
		}
		if skipped < 5 {
			t.Errorf("minCommits=%d: want >=5 replicas (2 re-adds x 2 files + cherry-picked modify), got %d", minCommits, skipped)
		}
	}
}

func TestParseDiffKey(t *testing.T) {
	a, b := strings.Repeat("a", 40), strings.Repeat("b", 40)
	if _, ok := parseDiffKey("p", "index "+a+".."+b+" 100644\n"); !ok {
		t.Fatal("full ids rejected")
	}
	for _, bad := range []string{"index abc..def\n", "index " + a + "\n", "index " + a + ".." + strings.Repeat("z", 40) + "\n"} {
		if _, ok := parseDiffKey("p", bad); ok {
			t.Errorf("accepted %q", bad)
		}
	}
	var r *diffReplicaRegistry
	if set, skip := r.claim("p", "index "+a+".."+b, &nativeCommit{hash: "c"}); set != nil || skip {
		t.Error("nil registry must always scan")
	}
}
