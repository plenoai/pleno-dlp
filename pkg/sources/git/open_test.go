package git

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestChunks_WorktreeConfigScansAndLeavesConfigUntouched covers the issue-380
// regression: a regular repository that declares extensions.worktreeConfig
// must scan normally, and the extension tolerance is an in-memory view —
// the config file on disk stays byte-identical.
func TestChunks_WorktreeConfigScansAndLeavesConfigUntouched(t *testing.T) {
	requireNativeGit(t)
	dir, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
		{files: map[string]string{"b.txt": "beta"}, msg: "c2"},
	})
	setGitConfig(t, dir, "extensions.worktreeConfig", "true")

	cfgPath := filepath.Join(dir, ".git", "config")
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks on worktreeConfig repo: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(got))
	}
	if got[0].SourceMetadata.Git == nil || got[0].SourceMetadata.Git.Commit != hashes[0] || got[0].SourceMetadata.Git.File != "a.txt" {
		t.Fatalf("first chunk metadata wrong: %+v", got[0].SourceMetadata.Git)
	}
	if got[1].SourceMetadata.Git.Commit != hashes[1] || got[1].SourceMetadata.Git.File != "b.txt" {
		t.Fatalf("second chunk metadata wrong: %+v", got[1].SourceMetadata.Git)
	}

	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("scan modified the repository config on disk")
	}
}

// TestChunks_LinkedWorktreeResolvesCommonDir scans a `git worktree add`
// linked worktree: its `.git` file points at the per-worktree gitdir and that
// gitdir's commondir file points back at the shared object store. The shared
// config also declares worktreeConfig — the exact layout real `git worktree`
// checkouts produce.
func TestChunks_LinkedWorktreeResolvesCommonDir(t *testing.T) {
	requireNativeGit(t)
	dir, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
		{files: map[string]string{"b.txt": "beta"}, msg: "c2"},
	})
	setGitConfig(t, dir, "extensions.worktreeConfig", "true")

	linked := filepath.Join(t.TempDir(), "linked")
	cmd := exec.Command("git", "-C", dir, "worktree", "add", "--detach", linked, "HEAD")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git worktree add: %v\n%s", err, out)
	}
	gitFile := filepath.Join(linked, ".git")
	if fi, err := os.Stat(gitFile); err != nil || fi.IsDir() {
		t.Fatalf("linked worktree .git is not a file: %v", err)
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: linked})
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks on linked worktree: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(got))
	}
	for i, want := range hashes {
		if got[i].SourceMetadata.Git.Commit != want {
			t.Fatalf("chunk %d commit: got %q want %q", i, got[i].SourceMetadata.Git.Commit, want)
		}
	}
}

// TestInit_RejectsUnknownExtension keeps the fail-closed behavior: an
// extension outside the ignorable set still surfaces go-git's verifier error
// instead of being silently dropped.
func TestInit_RejectsUnknownExtension(t *testing.T) {
	requireNativeGit(t)
	dir, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "one"}, msg: "c1"}})
	setGitConfig(t, dir, "extensions.frobnicate", "true")

	s := &Source{}
	raw, err := json.Marshal(Config{Repo: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 2); err == nil {
		t.Fatal("repository with an unknown extension opened successfully")
	} else if !strings.Contains(err.Error(), "frobnicate") {
		t.Fatalf("error does not name the offending extension: %v", err)
	}
}

// TestFilterConfigExtensions verifies only the ignorable option keys are
// dropped, sections/subsections are respected, and all other bytes survive.
func TestFilterConfigExtensions(t *testing.T) {
	in := "[core]\n" +
		"\trepositoryformatversion = 1\n" +
		"[extensions]\n" +
		"\tworktreeConfig = true\n" +
		"\tpartialClone = origin\n" +
		"\tpreciousObjects\n" +
		"\tobjectFormat = sha256\n" +
		"\t; keep this comment\n" +
		"[remote \"origin\"]\n" +
		"\tpromisor = true\n" +
		"[extensions.sub]\n" +
		"\tworktreeConfig = true\n"
	want := "[core]\n" +
		"\trepositoryformatversion = 1\n" +
		"[extensions]\n" +
		"\tobjectFormat = sha256\n" +
		"\t; keep this comment\n" +
		"[remote \"origin\"]\n" +
		"\tpromisor = true\n" +
		"[extensions.sub]\n" +
		"\tworktreeConfig = true\n"
	if got := string(filterConfigExtensions([]byte(in))); got != want {
		t.Fatalf("filter mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func setGitConfig(t *testing.T, dir, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "config", key, value)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config %s: %v\n%s", key, err, out)
	}
}
