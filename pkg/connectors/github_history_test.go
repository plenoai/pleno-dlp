package connectors

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestDeriveCloneURL(t *testing.T) {
	tests := []struct {
		name     string
		apiBase  string
		owner    string
		repo     string
		template string
		want     string
	}{
		{
			name:    "public default",
			apiBase: "https://api.github.com",
			owner:   "acme", repo: "widget",
			want: "https://github.com/acme/widget.git",
		},
		{
			name:    "public default trailing slash",
			apiBase: "https://api.github.com/",
			owner:   "acme", repo: "widget",
			want: "https://github.com/acme/widget.git",
		},
		{
			name:    "GHE api/v3",
			apiBase: "https://ghe.example/api/v3",
			owner:   "acme", repo: "widget",
			want: "https://ghe.example/acme/widget.git",
		},
		{
			name:    "GHE api/v3 trailing slash",
			apiBase: "https://ghe.example/api/v3/",
			owner:   "acme", repo: "widget",
			want: "https://ghe.example/acme/widget.git",
		},
		{
			name:    "GHE bare host",
			apiBase: "https://git.example",
			owner:   "acme", repo: "widget",
			want: "https://git.example/acme/widget.git",
		},
		{
			name:    "GHE subpath host",
			apiBase: "https://corp.example/github/api/v3",
			owner:   "acme", repo: "widget",
			want: "https://corp.example/github/acme/widget.git",
		},
		{
			name:    "template override placeholders",
			apiBase: "https://api.github.com",
			owner:   "acme", repo: "widget",
			template: "/tmp/fixtures/{owner}/{repo}",
			want:     "/tmp/fixtures/acme/widget",
		},
		{
			name:    "template override literal local path",
			apiBase: "https://api.github.com",
			owner:   "acme", repo: "widget",
			template: "/tmp/fixtures/fixed.git",
			want:     "/tmp/fixtures/fixed.git",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := deriveCloneURL(tc.apiBase, tc.owner, tc.repo, tc.template)
			if err != nil {
				t.Fatalf("deriveCloneURL: %v", err)
			}
			if got != tc.want {
				t.Fatalf("deriveCloneURL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestGitHubHostAndBlobLink(t *testing.T) {
	if got := githubHostFromAPIBase("https://api.github.com"); got != "github.com" {
		t.Errorf("host(public) = %q, want github.com", got)
	}
	if got := githubHostFromAPIBase("https://ghe.example/api/v3"); got != "ghe.example" {
		t.Errorf("host(ghe) = %q, want ghe.example", got)
	}
	withLine := githubBlobLink("github.com", "acme", "widget", "deadbeef", "a/b.go", 7)
	if withLine != "https://github.com/acme/widget/blob/deadbeef/a/b.go#L7" {
		t.Errorf("link with line = %q", withLine)
	}
	noLine := githubBlobLink("github.com", "acme", "widget", "deadbeef", "a/b.go", 0)
	if noLine != "https://github.com/acme/widget/blob/deadbeef/a/b.go" {
		t.Errorf("link no line = %q", noLine)
	}
	if strings.Contains(noLine, "#L") {
		t.Errorf("link with line=0 must omit #L: %q", noLine)
	}
}

func TestGitHubBlobLinkEscapesPathAndRendersArchiveOuterBlob(t *testing.T) {
	got := githubBlobLink("github.com", "acme", "widget", "abc", "dir/a #?% 日本.zip!../inner secret.txt", 9)
	want := "https://github.com/acme/widget/blob/abc/dir/a%20%23%3F%25%20%E6%97%A5%E6%9C%AC.zip#L9"
	if got != want {
		t.Fatalf("link=%q want=%q", got, want)
	}
	if got := githubBlobLink("github.com", "a", "b", "c", "../escape", 1); got != "" {
		t.Fatalf("traversal link=%q", got)
	}
}

// buildFixtureRepo creates a repo with a main branch and a side branch whose
// tip commit is reachable only from the side branch. Returns the repo dir and
// the side-only file name.
func buildFixtureRepo(t *testing.T) (dir string, sideFile string) {
	t.Helper()
	dir = t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commit := func(files map[string]string, msg string, when time.Time) {
		for p, c := range files {
			if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := wt.Add(p); err != nil {
				t.Fatalf("add: %v", err)
			}
		}
		if _, err := wt.Commit(msg, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "T", Email: "t@e.com", When: when},
			Committer: &object.Signature{Name: "T", Email: "t@e.com", When: when},
		}); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	commit(map[string]string{"main.txt": "AKIAIOSFODNN7MAINKEY"}, "c1", base)
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("feature"), Create: true}); err != nil {
		t.Fatalf("checkout -b feature: %v", err)
	}
	commit(map[string]string{"side.txt": "AKIAIOSFODNN7SIDEKEY"}, "c2-side", base.Add(time.Minute))
	return dir, "side.txt"
}

func TestGitHubHistoryScanEmitsAllBranches(t *testing.T) {
	fixture, sideFile := buildFixtureRepo(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widget":
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "public"})
		default:
			t.Fatalf("history mode must not hit unexpected REST path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":              "ghp_test",
		"repo":               "acme/widget",
		"api_base":           srv.URL,
		"clone_url_template": fixture,
	}

	type emitted struct {
		data []byte
		meta sources.GitHubMeta
	}
	var got []emitted
	var mu sync.Mutex
	err := scanGitHub(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		mu.Lock()
		defer mu.Unlock()
		if meta.GitHub == nil {
			t.Errorf("history chunk missing GitHub metadata; Git=%v", meta.Git)
			return nil
		}
		if meta.Git != nil {
			t.Errorf("history connector must not emit GitMeta")
		}
		got = append(got, emitted{data: data, meta: *meta.GitHub})
		return nil
	})
	if err != nil {
		t.Fatalf("scanGitHub history: %v", err)
	}

	files := map[string]sources.GitHubMeta{}
	for _, e := range got {
		files[e.meta.File] = e.meta
	}
	if _, ok := files["main.txt"]; !ok {
		t.Fatalf("history scan missing main.txt; files=%v", keys(files))
	}
	sideMeta, ok := files[sideFile]
	if !ok {
		t.Fatalf("history scan missing side-branch file %q; files=%v", sideFile, keys(files))
	}

	// Metadata shape assertions on the side-branch chunk.
	if sideMeta.Repository != "acme/widget" {
		t.Errorf("Repository = %q, want acme/widget", sideMeta.Repository)
	}
	if sideMeta.Owner != "acme" || sideMeta.Repo != "widget" {
		t.Errorf("Owner/Repo = %q/%q, want acme/widget", sideMeta.Owner, sideMeta.Repo)
	}
	if sideMeta.Commit == "" {
		t.Errorf("Commit empty")
	}
	if sideMeta.Path != sideFile {
		t.Errorf("Path = %q, want %q", sideMeta.Path, sideFile)
	}
	if sideMeta.Visibility != "public" {
		t.Errorf("Visibility = %q, want public", sideMeta.Visibility)
	}
	// The web-link host tracks api_base (same host serves UI + API on GHE).
	// With the injected httptest api_base, that is srv's host.
	wantHost := strings.TrimPrefix(srv.URL, "https://")
	wantHost = strings.TrimPrefix(wantHost, "http://")
	wantLinkPrefix := "https://" + wantHost + "/acme/widget/blob/" + sideMeta.Commit + "/" + sideFile
	if !strings.HasPrefix(sideMeta.Link, wantLinkPrefix) {
		t.Errorf("Link = %q, want prefix %q", sideMeta.Link, wantLinkPrefix)
	}
	if sideMeta.Line > 0 && !strings.Contains(sideMeta.Link, "#L") {
		t.Errorf("Link with line>0 missing #L fragment: %q", sideMeta.Link)
	}
}

func TestGitHubHistoryRepoWalkTimeout(t *testing.T) {
	fixture, _ := buildFixtureRepo(t)
	repo := githubRepoRef{Name: "widget", Visibility: "private"}
	repo.Owner.Login = "acme"
	next, err := scanGitHubGitHistory(context.Background(), Config{"repo_walk_timeout": "1ns"}, staticGitHubToken(""), "github.com", fixture, repo, githubRepoIncrementalState{}, false, nil, func([]byte, sources.Metadata) error {
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("walk error = %v, want context deadline", err)
	}
	if !strings.Contains(err.Error(), "acme/widget") || !strings.Contains(err.Error(), "1ns") {
		t.Fatalf("walk timeout lacks repository/budget: %v", err)
	}
	if len(next.RefHeads) != 0 {
		t.Fatalf("timed-out walk advanced state: %#v", next)
	}
}

func TestGitHubRepoWalkTimeoutValidation(t *testing.T) {
	for _, raw := range []string{"invalid", "-1s"} {
		if _, err := githubRepoWalkTimeout(Config{"repo_walk_timeout": raw}); err == nil {
			t.Fatalf("repo_walk_timeout %q accepted", raw)
		}
	}
	for _, raw := range []string{"", "0", "0s"} {
		if got, err := githubRepoWalkTimeout(Config{"repo_walk_timeout": raw}); err != nil || got != 0 {
			t.Fatalf("repo_walk_timeout %q = %s, %v", raw, got, err)
		}
	}
}

func TestGitHubHistoryScanStreamsLargeModification(t *testing.T) {
	const secret = "github_pat_11AAABBB_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	var base strings.Builder
	for i := 0; i < 220000; i++ {
		base.WriteString("large fixture line\n")
	}
	commit := func(content, message string, minute int) {
		if err := os.WriteFile(filepath.Join(dir, "big.txt"), []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := wt.Add("big.txt"); err != nil {
			t.Fatalf("add: %v", err)
		}
		when := time.Date(2026, 5, 1, 0, minute, 0, 0, time.UTC)
		if _, err := wt.Commit(message, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "T", Email: "t@e.com", When: when},
			Committer: &object.Signature{Name: "T", Email: "t@e.com", When: when},
		}); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	commit(base.String(), "large base", 0)
	commit(base.String()+secret+"\n", "add secret", 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget" {
			t.Fatalf("unexpected REST path: %s", r.URL.String())
		}
		writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "private"})
	}))
	t.Cleanup(srv.Close)

	found := false
	err = scanGitHub(context.Background(), Config{
		"token":              "ghp_test",
		"repo":               "acme/widget",
		"api_base":           srv.URL,
		"clone_url_template": dir,
	}, func(data []byte, meta sources.Metadata) error {
		if meta.GitHub != nil && strings.Contains(string(data), secret) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanGitHub history: %v", err)
	}
	if !found {
		t.Fatal("GitHub history scan missed secret added to a >1 MiB file")
	}
}

func TestGitHubHistoryCommitMetadataAndNotes(t *testing.T) {
	const noteSecret = "github_pat_11GHNOTE__abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "safe.txt"), []byte("safe\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := wt.Add("safe.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	hash, err := wt.Commit("metadata fixture", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "T", Email: "expected-pii@example.com", When: when},
		Committer: &object.Signature{Name: "T", Email: "expected-pii@example.com", When: when},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if out, err := exec.Command("git", "-C", dir, "-c", "user.name=Test", "-c", "user.email=test@example.com", "notes", "add", "-m", noteSecret, hash.String()).CombinedOutput(); err != nil {
		t.Fatalf("git notes add: %v: %s", err, out)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "private"})
	}))
	t.Cleanup(srv.Close)
	var metadata *sources.GitHubMeta
	found := false
	err = scanGitHub(context.Background(), Config{
		"token": "ghp_test", "repo": "acme/widget", "api_base": srv.URL,
		"clone_url_template": dir, "include_commit_metadata": "true",
	}, func(data []byte, meta sources.Metadata) error {
		if strings.Contains(string(data), noteSecret) {
			found, metadata = true, meta.GitHub
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanGitHub: %v", err)
	}
	if !found || metadata == nil {
		t.Fatal("GitHub scan missed opted-in git note")
	}
	if !strings.HasPrefix(metadata.Path, "commit:metadata/") || !strings.Contains(metadata.Link, "/commit/"+hash.String()) {
		t.Fatalf("metadata provenance = %#v", metadata)
	}
}

func TestGitHubHistoryScansOptInArchive(t *testing.T) {
	const secret = "github_pat_11GHZIP___abcdefghijklmnopqrstuvwxyz0123456789"
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	f, _ := zw.Create("nested/secret.txt")
	_, _ = f.Write([]byte(secret))
	_ = zw.Close()
	dir := t.TempDir()
	repo, _ := gogit.PlainInit(dir, false)
	wt, _ := repo.Worktree()
	if err := os.WriteFile(filepath.Join(dir, "payload.zip"), zipped.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = wt.Add("payload.zip")
	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	_, err := wt.Commit("archive", &gogit.CommitOptions{Author: &object.Signature{Name: "T", Email: "t@e", When: when}, Committer: &object.Signature{Name: "T", Email: "t@e", When: when}})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "private"})
	}))
	defer srv.Close()
	found := false
	err = scanGitHub(context.Background(), Config{"token": "x", "repo": "acme/widget", "api_base": srv.URL, "clone_url_template": dir, "include_git_archives": "true"}, func(data []byte, meta sources.Metadata) error {
		found = found || (strings.Contains(string(data), secret) && meta.GitHub != nil && strings.Contains(meta.GitHub.Path, "payload.zip!nested/secret.txt"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("GitHub archive history missed nested secret")
	}
}

func TestGitHubHistoryIncrementalEmitsOnlyNewCommits(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commit := func(p, c, msg string, when time.Time) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := wt.Add(p); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, err := wt.Commit(msg, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "T", Email: "t@e.com", When: when},
			Committer: &object.Signature{Name: "T", Email: "t@e.com", When: when},
		}); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	commit("a.txt", "secret-a", "c1", base)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widget" {
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "public"})
			return
		}
		t.Fatalf("unexpected REST path: %s", r.URL.String())
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":              "ghp_test",
		"repo":               "acme/widget",
		"api_base":           srv.URL,
		"clone_url_template": dir,
	}

	collect := func() []string {
		var files []string
		var mu sync.Mutex
		if err := scanGitHub(context.Background(), cfg, func(_ []byte, meta sources.Metadata) error {
			mu.Lock()
			defer mu.Unlock()
			if meta.GitHub != nil {
				files = append(files, meta.GitHub.File)
			}
			return nil
		}); err != nil {
			t.Fatalf("scanGitHub: %v", err)
		}
		sort.Strings(files)
		return files
	}

	first := collect()
	if strings.Join(first, ",") != "a.txt" {
		t.Fatalf("first run files = %v, want [a.txt]", first)
	}
	state := cfg[configKeyIncrementalNextState]
	if state == "" {
		t.Fatal("first run produced no incremental state")
	}

	// Add a new commit, rerun seeded with prior state.
	commit("b.txt", "secret-b", "c2", base.Add(time.Minute))
	cfg[configKeyIncrementalPreviousState] = state
	delete(cfg, configKeyIncrementalNextState)

	second := collect()
	if strings.Join(second, ",") != "b.txt" {
		t.Fatalf("second run files = %v, want only [b.txt]", second)
	}
}

// pushed_at が前回 walk 時から動いていない repo は clone/walk ごと skip され、
// state はそのまま carry される。 pushed_at が動けば skip が外れ、 carry され
// ていた RefHeads を seed に incremental walk が新規 commit だけを emit する。
func TestGitHubHistoryPushedAtSkipsUnchangedRepo(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commit := func(p, c, msg string, when time.Time) {
		if err := os.WriteFile(filepath.Join(dir, p), []byte(c), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := wt.Add(p); err != nil {
			t.Fatalf("add: %v", err)
		}
		if _, err := wt.Commit(msg, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "T", Email: "t@e.com", When: when},
			Committer: &object.Signature{Name: "T", Email: "t@e.com", When: when},
		}); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	commit("a.txt", "secret-a", "c1", base)

	pushedAt := "2026-05-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widget" {
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "public", PushedAt: pushedAt})
			return
		}
		t.Fatalf("unexpected REST path: %s", r.URL.String())
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":              "ghp_test",
		"repo":               "acme/widget",
		"api_base":           srv.URL,
		"clone_url_template": dir,
	}

	collect := func() []string {
		var files []string
		var mu sync.Mutex
		if err := scanGitHub(context.Background(), cfg, func(_ []byte, meta sources.Metadata) error {
			mu.Lock()
			defer mu.Unlock()
			if meta.GitHub != nil {
				files = append(files, meta.GitHub.File)
			}
			return nil
		}); err != nil {
			t.Fatalf("scanGitHub: %v", err)
		}
		sort.Strings(files)
		return files
	}

	first := collect()
	if strings.Join(first, ",") != "a.txt" {
		t.Fatalf("first run files = %v, want [a.txt]", first)
	}
	state := cfg[configKeyIncrementalNextState]
	if !strings.Contains(state, `"pushed_at":"`+pushedAt+`"`) {
		t.Fatalf("first run state missing pushed_at %s: %s", pushedAt, state)
	}

	// pushed_at 不変のまま fixture に commit を足す。 clone が skip されて
	// いれば新 commit は見えない — emit ゼロが skip 発動の観測点。
	commit("b.txt", "secret-b", "c2", base.Add(time.Minute))
	cfg[configKeyIncrementalPreviousState] = state
	delete(cfg, configKeyIncrementalNextState)

	second := collect()
	if len(second) != 0 {
		t.Fatalf("second run files = %v, want none (clone skipped)", second)
	}
	carried := cfg[configKeyIncrementalNextState]
	if !strings.Contains(carried, `"ref_heads"`) || !strings.Contains(carried, `"pushed_at":"`+pushedAt+`"`) {
		t.Fatalf("skip did not carry state forward: %s", carried)
	}

	// pushed_at が動くと skip が外れ、 carry されていた RefHeads を seed に
	// 新規 commit だけが emit される。
	pushedAt = "2026-05-01T01:00:00Z"
	cfg[configKeyIncrementalPreviousState] = carried
	delete(cfg, configKeyIncrementalNextState)

	third := collect()
	if strings.Join(third, ",") != "b.txt" {
		t.Fatalf("third run files = %v, want only [b.txt]", third)
	}
	if !strings.Contains(cfg[configKeyIncrementalNextState], `"pushed_at":"`+pushedAt+`"`) {
		t.Fatalf("third run state did not record new pushed_at: %s", cfg[configKeyIncrementalNextState])
	}

	// Changing the history policy invalidates both the clone skip and the
	// previous ref-head stop set. With pushed_at unchanged, the existing
	// commits must be emitted again under the new diff semantics.
	cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
	delete(cfg, configKeyIncrementalNextState)
	cfg["trufflehog_compatible"] = "true"

	fourth := collect()
	if strings.Join(fourth, ",") != "a.txt,b.txt" {
		t.Fatalf("policy-change run files = %v, want full rescan [a.txt b.txt]", fourth)
	}
}

// fingerprint は repo list のメタデータ (pushed_at / updated_at) だけで
// 決まる。 push が pushed_at を動かせば fingerprint が変わり、 skip
// fast-path が外れて scan 本体が走る。 per-repo の git / comment アクセスは
// fingerprint 段階では発生しない (unexpected REST path を Fatalf で防ぐ)。
func TestGitHubHistoryFingerprintTracksPushedAt(t *testing.T) {
	pushedAt := "2026-05-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/acme/widget" {
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", PushedAt: pushedAt})
			return
		}
		t.Fatalf("fingerprint must not hit unexpected REST path: %s", r.URL.String())
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":    "ghp_test",
		"repo":     "acme/widget",
		"api_base": srv.URL,
	}
	first, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first fingerprint: %v", err)
	}
	if first == "" {
		t.Fatal("fingerprint must be non-empty without include_comments")
	}
	pushedAt = "2026-05-01T01:00:00Z"
	second, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second fingerprint: %v", err)
	}
	if first == second {
		t.Fatalf("fingerprint did not change after pushed_at moved: %s", first)
	}
}

// include_comments ではコメント編集が repo メタデータに現れないため、 安価な
// 全体 fingerprint が存在しない。 ("", nil) の opt-out (sources.
// ResourceFingerprinter 参照) を返し、 REST には一切触れないこと。
func TestGitHubHistoryFingerprintIncludeCommentsOptsOut(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("include_comments fingerprint must not call the API, got %s", r.URL.String())
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":            "ghp_test",
		"repo":             "acme/widget",
		"api_base":         srv.URL,
		"include_comments": "true",
	}
	fp, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("fingerprintGitHub: %v", err)
	}
	if fp != "" {
		t.Fatalf("include_comments fingerprint must opt out with empty string, got %q", fp)
	}
}

// TestGitHubHistoryScanComments exercises the REST comments surface
// (--include-comments) through the history scan path: comments are emitted on
// the first run and the incremental rerun emits only the comment whose
// updated_at changed. Code chunks come from the local clone fixture; comments
// come from the httptest REST server.
func TestGitHubHistoryScanComments(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("code-secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := wt.Add("a.txt"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := wt.Commit("c1", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "T", Email: "t@e.com", When: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
		Committer: &object.Signature{Name: "T", Email: "t@e.com", When: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	issueUpdated := "2026-06-09T00:00:00Z"
	pullUpdated := "2026-06-09T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widget":
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "master", Visibility: "public"})
		case "/repos/acme/widget/issues/comments":
			writeJSON(t, w, []githubIssueComment{{ID: 101, Body: "issue-secret", UpdatedAt: issueUpdated}})
		case "/repos/acme/widget/pulls/comments":
			writeJSON(t, w, []githubPullReviewComment{{ID: 202, Body: "pull-secret", Path: "a.txt", Position: 7, UpdatedAt: pullUpdated}})
		default:
			t.Fatalf("unexpected REST path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":              "ghp_test",
		"repo":               "acme/widget",
		"api_base":           srv.URL,
		"include_comments":   "true",
		"clone_url_template": dir,
	}

	collect := func() []string {
		var got []string
		var mu sync.Mutex
		if err := scanGitHub(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, string(data))
			return nil
		}); err != nil {
			t.Fatalf("scanGitHub: %v", err)
		}
		sort.Strings(got)
		return got
	}

	first := collect()
	if got, want := strings.Join(first, ","), "code-secret,issue-secret,pull-secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	state := cfg[configKeyIncrementalNextState]
	if state == "" {
		t.Fatal("first run produced no incremental state")
	}

	// Rerun seeded with prior state: code is unchanged (ref head identical) and
	// the issue comment is unchanged, so only the pull comment (new updated_at)
	// is re-emitted.
	pullUpdated = "2026-06-09T01:00:00Z"
	cfg[configKeyIncrementalPreviousState] = state
	delete(cfg, configKeyIncrementalNextState)

	second := collect()
	if got, want := strings.Join(second, ","), "pull-secret"; got != want {
		t.Fatalf("second emitted %q, want only changed comment %q", got, want)
	}
}

func keys(m map[string]sources.GitHubMeta) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// repo list の増減は fingerprint を変える (= repo の追加/削除で skip
// fast-path が外れる)。
func TestGitHubHistoryFingerprintTracksRepoSet(t *testing.T) {
	repos := []githubRepoRef{
		{Name: "repo1", Visibility: "public", PushedAt: "2026-05-01T00:00:00Z"},
		{Name: "repo2", Visibility: "public", PushedAt: "2026-05-01T00:00:00Z"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orgs/test-org/repos" {
			writeJSON(t, w, repos)
			return
		}
		t.Errorf("unexpected REST path: %s", r.URL.String())
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"org":      "test-org",
		"token":    "ghp_test",
		"api_base": srv.URL,
	}
	both, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("fingerprintGitHub (2 repos): %v", err)
	}
	repos = repos[:1]
	one, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("fingerprintGitHub (1 repo): %v", err)
	}
	if both == one {
		t.Fatalf("fingerprint must differ when the repo set changes; got identical %q", both)
	}
}
