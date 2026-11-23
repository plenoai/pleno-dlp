package connectors

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// newTestGitRepo initialises a non-bare repository in a temp dir and
// returns its path plus a helper that commits cfg.env with content. The
// path doubles as a credential-free clone URL for scanRemoteGitRepo.
func newTestGitRepo(t *testing.T) (string, func(content string)) {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	return dir, func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "cfg.env"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		wt, err := repo.Worktree()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wt.Add("cfg.env"); err != nil {
			t.Fatal(err)
		}
		sig := &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}
		if _, err := wt.Commit(content, &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
			t.Fatal(err)
		}
	}
}
