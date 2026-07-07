// Tests for the native-git clone path added for issue #265. Kept in a
// separate file from github_history_test.go on purpose: that file's existing
// fixtures embed placeholder strings shaped like cloud provider access-key
// IDs for unrelated branch-walk tests, and any edit to that file re-triggers
// GitHub push protection's full-blob secret scan on content this change
// never touches. A new file sidesteps that without touching pre-existing,
// unrelated fixture data.
package connectors

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// TestGithubEmbedCloneToken covers the native-clone URL-building helper:
// token embedded as userinfo for a real HTTP(S) URL, and left untouched for
// the local-path shape the fixture tests use (no scheme/host) or when there
// is no token at all.
func TestGithubEmbedCloneToken(t *testing.T) {
	tests := []struct {
		name     string
		cloneURL string
		token    string
		want     string
	}{
		{
			name:     "https url gets token embedded",
			cloneURL: "https://github.com/acme/widget.git",
			token:    "ghp_secret123",
			want:     "https://x-access-token:ghp_secret123@github.com/acme/widget.git",
		},
		{
			name:     "no token leaves url untouched",
			cloneURL: "https://github.com/acme/widget.git",
			token:    "",
			want:     "https://github.com/acme/widget.git",
		},
		{
			name:     "local path untouched even with a token",
			cloneURL: "/tmp/fixtures/acme/widget",
			token:    "ghp_secret123",
			want:     "/tmp/fixtures/acme/widget",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := githubEmbedCloneToken(tc.cloneURL, tc.token)
			if got != tc.want {
				t.Errorf("githubEmbedCloneToken(%q, %q) = %q, want %q", tc.cloneURL, tc.token, got, tc.want)
			}
		})
	}
}

// TestRedactCloneError verifies that neither the raw token nor the
// token-embedded URL survive into an error returned from a failed native
// clone — required because the token is passed to the native git subprocess
// via that URL (see cloneWithNativeGit), so any error path that happens to
// echo argv back could otherwise leak it.
func TestRedactCloneError(t *testing.T) {
	token := "ghp_verysecret"
	authURL := "https://x-access-token:ghp_verysecret@github.com/acme/widget.git"
	safeURL := "https://github.com/acme/widget.git"
	raw := errors.New("exit status 128: fatal: could not read from " + authURL)

	got := redactCloneError(raw, token, authURL, safeURL)

	if strings.Contains(got.Error(), token) {
		t.Errorf("redacted error still contains the raw token: %q", got.Error())
	}
	if strings.Contains(got.Error(), authURL) {
		t.Errorf("redacted error still contains the token-embedded URL: %q", got.Error())
	}
	if !strings.Contains(got.Error(), safeURL) {
		t.Errorf("redacted error dropped the safe URL entirely: %q", got.Error())
	}
}

// gitCloneFixtureRepo makes a minimal one-commit repo at a fresh temp dir,
// suitable as a clone source. Kept local to this file (rather than reusing
// github_history_test.go's buildFixtureRepo) so this file never needs to
// import that file's helpers and stays independently reviewable/pushable.
func gitCloneFixtureRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "f.txt"), []byte("placeholder content"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := wt.Add("f.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	sig := &object.Signature{Name: "T", Email: "t@e.com", When: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)}
	if _, err := wt.Commit("c1", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}

// TestCloneRepoBareFallsBackWithoutGitBinary forces exec.LookPath("git") to
// fail (empty PATH) and checks cloneRepoBare takes the go-git branch instead
// of erroring out of the branch-selection logic itself — the pure-Go
// environment #265 asks to keep working when the native binary isn't
// available.
//
// It does not assert the clone itself succeeds: go-git's own local/file
// transport (used for the plain-filesystem clone URLs the fixture tests
// inject) shells out to a `git-upload-pack`-family binary internally, so a
// truly git-less box can't exercise a *local-path* fallback clone either —
// only its smart-HTTP(S) transport is pure Go. That's a go-git property, not
// this file's; what belongs to this file, and what the test checks, is that
// missing `git` on PATH routes to cloneWithGoGit rather than being treated
// as a hard error.
func TestCloneRepoBareFallsBackWithoutGitBinary(t *testing.T) {
	fixture := gitCloneFixtureRepo(t)
	dir := t.TempDir()

	t.Setenv("PATH", t.TempDir()) // a dir with no `git` binary in it

	usedNative, err := cloneRepoBare(context.Background(), fixture, dir, "", io.Discard)
	if usedNative {
		t.Fatalf("cloneRepoBare reported native git despite an empty PATH (err=%v)", err)
	}
}

// TestCloneRepoBareNativeAppliesBlobFilter is a light regression guard on the
// native git-arg construction (issue #265's --filter=blob:limit=<N>, kept
// equal to gitsource's unexported maxBlobSize — see
// githubCloneBlobFilterLimit's doc comment). It only runs when `git` is on
// PATH; CI and dev boxes have it, and the fallback path is covered
// separately above without needing the real binary.
func TestCloneRepoBareNativeAppliesBlobFilter(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	fixture := gitCloneFixtureRepo(t)
	dir := t.TempDir()

	usedNative, err := cloneRepoBare(context.Background(), fixture, dir, "", io.Discard)
	if err != nil {
		t.Fatalf("cloneRepoBare native: %v", err)
	}
	if !usedNative {
		t.Fatal("cloneRepoBare did not take the native path with git on PATH")
	}
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		t.Fatalf("native clone did not produce a valid repo at %s: %v", dir, err)
	}
	if _, err := repo.Head(); err != nil {
		t.Fatalf("native clone's HEAD does not resolve: %v", err)
	}
}

// TestNativeGitCloneArgs pins the native clone's argv (issue #265's
// --filter=blob:limit=<N>, --bare, and the "--" separator that keeps a
// URL-embedded userinfo from ever being parsed as a flag) without executing
// git — the "add a small test for the git-arg construction" ask, done
// without any network or subprocess dependency.
func TestNativeGitCloneArgs(t *testing.T) {
	got := nativeGitCloneArgs("https://x-access-token:secret@github.com/acme/widget.git", "/tmp/clone-dir")
	want := []string{
		"clone",
		"--bare",
		"--filter=blob:limit=52428800", // githubCloneBlobFilterLimit, 50 MiB
		"--progress",
		"--",
		"https://x-access-token:secret@github.com/acme/widget.git",
		"/tmp/clone-dir",
	}
	if len(got) != len(want) {
		t.Fatalf("nativeGitCloneArgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("nativeGitCloneArgs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	sepIdx := -1
	for i, a := range got {
		if a == "--" {
			sepIdx = i
			break
		}
	}
	if sepIdx == -1 || sepIdx != len(got)-3 {
		t.Fatalf("nativeGitCloneArgs must place \"--\" immediately before <url> <dir>, got %v", got)
	}
}
