package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
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
