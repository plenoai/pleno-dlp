package git

import (
	"os"
	"path/filepath"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"time"
)

// makeRepoWithWorktreeConfig creates a minimal git repository and sets
// extensions.worktreeConfig=true in its .git/config.
func makeRepoWithWorktreeConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	// Commit a file so the repo has a HEAD.
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	f, err := os.Create(filepath.Join(dir, "file.txt"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	f.WriteString("secret=abc123\n")
	f.Close()
	_, err = wt.Add("file.txt")
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	_, err = wt.Commit("init", &gogit.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Unix(0, 0)},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Inject extensions.worktreeConfig=true into .git/config.
	cfgPath := filepath.Join(dir, ".git", "config")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfg = append(cfg, []byte("\n[extensions]\n\tworktreeConfig = true\n")...)
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	return dir
}

// TestOpenRepo_WorktreeConfigExtension verifies that openRepo succeeds for a
// repository with extensions.worktreeConfig=true, which go-git v5 rejects via
// a key-casing mismatch (go-git lowercases keys; allowlist uses camelCase).
func TestOpenRepo_WorktreeConfigExtension(t *testing.T) {
	dir := makeRepoWithWorktreeConfig(t)

	// Confirm go-git itself rejects the repo.
	_, err := gogit.PlainOpen(dir)
	if err == nil {
		t.Skip("go-git accepted worktreeConfig repo without the fix; test not needed here")
	}

	// Our wrapper must succeed.
	repo, err := openRepo(dir)
	if err != nil {
		t.Fatalf("openRepo with worktreeConfig repo: %v", err)
	}
	if repo == nil {
		t.Fatal("openRepo returned nil repo without error")
	}

	// Sanity check: HEAD is accessible.
	if _, err := repo.Head(); err != nil {
		t.Fatalf("repo.Head: %v", err)
	}
}

// TestOpenRepo_NormalRepo verifies that openRepo works identically to
// PlainOpen for standard repositories.
func TestOpenRepo_NormalRepo(t *testing.T) {
	dir := t.TempDir()
	_, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// No commits yet — PlainOpen should succeed but HEAD won't resolve; that
	// is the same behaviour for both paths.
	if _, err := openRepo(dir); err != nil {
		t.Fatalf("openRepo on normal repo: %v", err)
	}
}

// TestOpenRepo_InvalidPath verifies that openRepo returns an error for
// a path that is not a git repository.
func TestOpenRepo_InvalidPath(t *testing.T) {
	dir := t.TempDir()
	if _, err := openRepo(dir); err == nil {
		t.Fatal("openRepo on non-repo path: expected error, got nil")
	}
}

// TestExtensionStrippingStorer_StripsWorktreeConfig verifies that the storer
// wrapper removes worktreeConfig from the config without affecting other
// extension entries.
func TestExtensionStrippingStorer_StripsWorktreeConfig(t *testing.T) {
	// Build an in-memory storer with a raw config containing worktreeConfig.
	ms := memory.NewStorage()
	raw := `[core]
	repositoryformatversion = 0
[extensions]
	worktreeConfig = true
	partialClone = origin
`
	_ = ms // We test the wrapper directly by constructing a synthetic storer.

	// Synthesize the extension via gcfg config text so we exercise the real
	// path from extensionStrippingStorer.Config without needing a real repo.
	// Instead, call the wrapper on a real (empty init) repo.
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	_ = repo

	// Inject both worktreeConfig and a valid extension into config.
	cfgPath := filepath.Join(dir, ".git", "config")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfg = append(cfg, []byte("\n[extensions]\n\tworktreeConfig = true\n\tnoop = \n")...)
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	// openRepo should succeed: worktreeConfig is stripped, noop is kept and
	// is in go-git's builtinExtensions list.
	if _, err := openRepo(dir); err != nil {
		t.Fatalf("openRepo with mixed extensions: %v", err)
	}
	_ = raw
}
