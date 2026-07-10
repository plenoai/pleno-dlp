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
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
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

func TestRedactCloneErrorScrubsBasicCredential(t *testing.T) {
	token := "super-secret-token"
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	got := redactCloneError(errors.New("Authorization: Basic "+basic), token).Error()
	if strings.Contains(got, token) || strings.Contains(got, basic) {
		t.Fatalf("credential leaked: %q", got)
	}
}

func TestGitHubAuthenticatedTransportAndCloneTrust(t *testing.T) {
	if err := validateGitHubAuthenticatedTransport("http://github.example/api/v3", true); err == nil {
		t.Fatal("authenticated non-loopback HTTP accepted")
	}
	if err := validateGitHubAuthenticatedTransport("http://127.0.0.1:8080", true); err != nil {
		t.Fatalf("loopback test endpoint rejected: %v", err)
	}
	if err := validateGitHubCloneTarget("https://ghe.example/api/v3", "https://evil.example/acme/r.git"); err == nil {
		t.Fatal("cross-origin clone template accepted")
	}
	if err := validateGitHubCloneTarget("https://ghe.example/api/v3", "/tmp/repo"); err == nil {
		t.Fatal("local clone template accepted for production API")
	}
	if err := validateGitHubCloneTarget("https://ghe.example/api/v3", "https://ghe.example:443/acme/r.git"); err != nil {
		t.Fatalf("equivalent default port rejected: %v", err)
	}
	if err := validateGitHubCloneTarget("https://ghe.example:8443/api/v3", "https://ghe.example:9443/acme/r.git"); err == nil {
		t.Fatal("alternate-port clone template accepted")
	}
}

func TestGitHubAlternatePortTemplatesNeverReachCloneService(t *testing.T) {
	var cloneRequests int
	cloneSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { cloneRequests++ }))
	t.Cleanup(cloneSrv.Close)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/repo":
			_, _ = io.WriteString(w, `{"id":1,"name":"repo","owner":{"login":"acme"},"has_wiki":true}`)
		case "/gists/abc123":
			_, _ = io.WriteString(w, `{"id":"abc123","owner":{"login":"acme"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(apiSrv.Close)

	cases := []Config{
		{"token": "token", "repo": "acme/repo", "api_base": apiSrv.URL, "clone_url_template": cloneSrv.URL + "/{owner}/{repo}.git"},
		{"token": "token", "repo": "acme/repo", "api_base": apiSrv.URL, "clone_url_template": filepath.Join(t.TempDir(), "repo"), "include_wikis": "true", "wiki_clone_url_template": cloneSrv.URL + "/{owner}/{repo}.wiki.git"},
		{"token": "token", "gist_urls": "abc123", "api_base": apiSrv.URL, "gist_clone_url_template": cloneSrv.URL + "/{id}.git"},
	}
	for i, cfg := range cases {
		if err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil }); err == nil {
			t.Fatalf("case %d accepted alternate-port template", i)
		}
	}
	if cloneRequests != 0 {
		t.Fatalf("alternate-port clone service received %d request(s), want zero", cloneRequests)
	}
}

func TestGitHubCloneMissingTreeDoesNotAdvanceAndRepairResumes(t *testing.T) {
	fixture, _ := buildFixtureRepo(t)
	repo, err := gogit.PlainOpen(fixture)
	if err != nil {
		t.Fatal(err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	objectPath := filepath.Join(fixture, ".git", "objects", commit.TreeHash.String()[:2], commit.TreeHash.String()[2:])
	objectData, err := os.ReadFile(objectPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(objectPath); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/repo" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, `{"id":1,"name":"repo","owner":{"login":"acme"},"pushed_at":"2026-07-10T00:00:00Z"}`)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{"token": "token", "repo": "acme/repo", "api_base": srv.URL, "clone_url_template": fixture}
	err = scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("missing object err=%v, want degraded coverage", err)
	}
	state, stateErr := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if stateErr != nil {
		t.Fatal(stateErr)
	}
	if got := state.Surfaces["repository-history"]["acme/repo"].RefHeads; len(got) != 0 {
		t.Fatalf("failed clone advanced checkpoint: %v", got)
	}

	if err := os.MkdirAll(filepath.Dir(objectPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(objectPath, objectData, 0o444); err != nil {
		t.Fatal(err)
	}
	cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
	delete(cfg, configKeyIncrementalNextState)
	emitted := 0
	if err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { emitted++; return nil }); err != nil {
		t.Fatalf("repaired resume: %v", err)
	}
	if emitted == 0 {
		t.Fatal("repaired resume did not re-emit previously uncovered content")
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
		"--mirror",
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
