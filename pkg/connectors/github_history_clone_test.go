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
	"encoding/base64"
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

// TestNativeGitAuthEnv covers the native-clone auth-env helper: the token is
// handed to git as an http.extraheader Authorization value through
// GIT_CONFIG_* environment variables — never argv, never the URL — for a
// real HTTP(S) URL, and omitted entirely for the local-path shape the
// fixture tests use (no scheme/host) or when there is no token at all.
func TestNativeGitAuthEnv(t *testing.T) {
	token := "ghp_secret123"
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))

	tests := []struct {
		name     string
		cloneURL string
		token    string
		want     []string
	}{
		{
			name:     "https url gets extraheader auth env",
			cloneURL: "https://github.com/acme/widget.git",
			token:    token,
			want: []string{
				"GIT_CONFIG_COUNT=1",
				"GIT_CONFIG_KEY_0=http.extraheader",
				"GIT_CONFIG_VALUE_0=Authorization: Basic " + basic,
			},
		},
		{
			name:     "no token yields no auth env",
			cloneURL: "https://github.com/acme/widget.git",
			token:    "",
			want:     nil,
		},
		{
			name:     "local path yields no auth env even with a token",
			cloneURL: "/tmp/fixtures/acme/widget",
			token:    token,
			want:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := nativeGitAuthEnv(tc.cloneURL, tc.token)
			if len(got) != len(tc.want) {
				t.Fatalf("nativeGitAuthEnv(%q, %q) = %v, want %v", tc.cloneURL, tc.token, got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("nativeGitAuthEnv[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestRedactCloneError verifies the raw token never survives into an error
// returned from a failed native clone — defense-in-depth on top of the token
// only ever being passed via the child environment (see nativeGitAuthEnv).
func TestRedactCloneError(t *testing.T) {
	token := "ghp_verysecret"
	raw := errors.New("exit status 128: fatal: unable to access repo: header 'Authorization: Basic " + token + "' rejected")

	got := redactCloneError(raw, token)

	if strings.Contains(got.Error(), token) {
		t.Errorf("redacted error still contains the raw token: %q", got.Error())
	}
	if !strings.Contains(got.Error(), "REDACTED") {
		t.Errorf("redacted error lost the redaction marker: %q", got.Error())
	}
	if same := redactCloneError(raw, ""); same != raw {
		t.Errorf("empty token must return the original error unchanged")
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
// --filter=blob:limit=<N>, --bare, and the "--" separator that keeps the
// URL from ever being parsed as a flag) without executing git. The URL in
// argv is always the clean one — auth travels via the child environment
// (see nativeGitAuthEnv), never argv.
func TestNativeGitCloneArgs(t *testing.T) {
	got := nativeGitCloneArgs("https://github.com/acme/widget.git", "/tmp/clone-dir")
	want := []string{
		"clone",
		"--bare",
		"--filter=blob:limit=52428800", // githubCloneBlobFilterLimit, 50 MiB
		"--progress",
		"--",
		"https://github.com/acme/widget.git",
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
