package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeRepoConfigOption(t *testing.T, repoPath, section, key, value string) {
	t.Helper()
	configPath := filepath.Join(repoPath, ".git", "config")
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	body = append(body, []byte("["+section+"]\n\t"+key+" = "+value+"\n")...)
	if err := os.WriteFile(configPath, body, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func TestOpenRepositoryWorktreeConfig(t *testing.T) {
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
	})
	writeRepoConfigOption(t, repo, "extensions", "worktreeConfig", "true")

	s := &Source{}
	mustInit(t, s, Config{Repo: repo})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 || string(got[0].Data) != "alpha" {
		t.Fatalf("chunks=%d, want the single committed file", len(got))
	}
	if got[0].SourceMetadata.Git == nil || got[0].SourceMetadata.Git.File != "a.txt" {
		t.Fatalf("metadata: %+v", got[0].SourceMetadata.Git)
	}
}

func TestOpenRepositoryRejectsUnknownExtensions(t *testing.T) {
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
	})
	writeRepoConfigOption(t, repo, "extensions", "unknownExtension", "true")

	if _, err := openRepository(repo); err == nil {
		t.Fatal("openRepository accepted an unknown extension")
	} else if !strings.Contains(err.Error(), "extension") {
		t.Fatalf("error %v does not name the rejected extension", err)
	}
}

// setupLinkedWorktree mirrors the on-disk layout `git worktree add` produces:
// a linked directory whose .git file points at <repo>/.git/worktrees/<name>,
// which in turn carries a commondir file back to the shared object store.
func setupLinkedWorktree(t *testing.T, repoPath, name string) string {
	t.Helper()
	linkedGitDir := filepath.Join(repoPath, ".git", "worktrees", name)
	if err := os.MkdirAll(linkedGitDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	head, err := os.ReadFile(filepath.Join(repoPath, ".git", "HEAD"))
	if err != nil {
		t.Fatalf("read HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(linkedGitDir, "HEAD"), head, 0o644); err != nil {
		t.Fatalf("write HEAD: %v", err)
	}
	if err := os.WriteFile(filepath.Join(linkedGitDir, "commondir"), []byte("../..\n"), 0o644); err != nil {
		t.Fatalf("write commondir: %v", err)
	}
	worktreeDir := t.TempDir()
	gitFile := []byte("gitdir: " + linkedGitDir + "\n")
	if err := os.WriteFile(filepath.Join(worktreeDir, ".git"), gitFile, 0o644); err != nil {
		t.Fatalf("write .git file: %v", err)
	}
	return worktreeDir
}

func TestOpenRepositoryLinkedWorktree(t *testing.T) {
	repo, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
	})
	writeRepoConfigOption(t, repo, "extensions", "worktreeConfig", "true")
	worktree := setupLinkedWorktree(t, repo, "linked")

	s := &Source{}
	mustInit(t, s, Config{Repo: worktree})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(got))
	}
	meta := got[0].SourceMetadata.Git
	if meta == nil || meta.Commit != hashes[0] || meta.File != "a.txt" {
		t.Fatalf("metadata: %+v, want commit %s file a.txt", meta, hashes[0])
	}
	if string(got[0].Data) != "alpha" {
		t.Fatalf("data: %q", got[0].Data)
	}

	// The go-git fallback path must walk the linked worktree identically.
	t.Setenv("PATH", t.TempDir())
	fallback := &Source{}
	mustInit(t, fallback, Config{Repo: worktree})
	got, err = drain(t, fallback, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks (go-git path): %v", err)
	}
	if len(got) != 1 || got[0].SourceMetadata.Git.Commit != hashes[0] || string(got[0].Data) != "alpha" {
		t.Fatalf("go-git chunks=%d, want the single committed file", len(got))
	}
}
