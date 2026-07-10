package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGistIDAndCloneURLDerivation(t *testing.T) {
	for _, raw := range []string{"abc123", "https://gist.github.com/alice/abc123", "https://ghe.example/gist/alice/abc123.git"} {
		base := githubDefaultAPIBase
		if strings.Contains(raw, "ghe.example") {
			base = "https://ghe.example/api/v3"
		}
		if got, err := gistID(context.Background(), raw, base); err != nil || got != "abc123" {
			t.Errorf("gistID(%q)=%q,%v", raw, got, err)
		}
	}
	if got, _ := deriveGistCloneURL(githubDefaultAPIBase, "abc123"); got != "https://gist.github.com/abc123.git" {
		t.Fatal(got)
	}
	if got, _ := deriveGistCloneURL("https://ghe.example/api/v3", "abc123"); got != "https://ghe.example/gist/abc123.git" {
		t.Fatal(got)
	}
}

func TestGistValidationRejectsHostileURLsBeforeCloneTokenLookup(t *testing.T) {
	for _, raw := range []string{"http://gist.github.com/a/deadbeef", "https://user:pass@gist.github.com/a/deadbeef", "https://evil.example/a/deadbeef", "https://gist.github.com/a/%2e%2e%2fdeadbeef"} {
		if _, err := gistID(context.Background(), raw, githubDefaultAPIBase); err == nil {
			t.Errorf("accepted %q", raw)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := gistID(ctx, "deadbeef", githubDefaultAPIBase); !errors.Is(err, context.Canceled) {
		t.Fatalf("err=%v", err)
	}
	provider := &countingWikiToken{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		g := githubGistRef{ID: "deadbeef", GitPullURL: "http://user:pass@evil.example/%2e%2e/repo.git"}
		writeJSON(t, w, g)
	}))
	t.Cleanup(srv.Close)
	err := scanGitHubGists(context.Background(), Config{"gist_urls": "deadbeef"}, provider, srv.URL, func([]byte, sources.Metadata) error { return nil })
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("err=%v", err)
	}
	if provider.calls != 1 {
		t.Fatalf("token calls=%d want API-only call 1", provider.calls)
	}
}

func TestGitHubMissingExplicitGistIsStructuredDegradation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	t.Cleanup(srv.Close)
	err := scanGitHub(context.Background(), Config{"token": "x", "api_base": srv.URL, "gist_urls": "deadbeef"}, func([]byte, sources.Metadata) error { return nil })
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("err=%v", err)
	}
}

func TestGitHubExplicitGistHistoryCommentsAndIncrementalState(t *testing.T) {
	fixture, _ := buildFixtureRepo(t)
	commentUpdated := "2026-07-10T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gists/abc123":
			g := githubGistRef{ID: "abc123", HTMLURL: "https://evil.example/phish", Public: false}
			g.Owner.Login = "alice"
			writeJSON(t, w, g)
		case "/gists/abc123/comments":
			writeJSON(t, w, []githubGistComment{{ID: 1, Body: "gist-comment-secret", UpdatedAt: commentUpdated, HTMLURL: "https://evil.example/comment"}, {ID: 2, Body: "  \n", UpdatedAt: commentUpdated, HTMLURL: "https://evil.example/empty"}})
		default:
			t.Fatalf("unexpected %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	cfg := Config{"token": "x", "api_base": srv.URL, "gist_urls": "https://gist.github.com/alice/abc123", "include_gist_comments": "true", "repo_concurrency": "2", "gist_clone_url_template": fixture}
	var got []sources.GitHubMeta
	var mu sync.Mutex
	err := scanGitHub(context.Background(), cfg, func(_ []byte, m sources.Metadata) error {
		if m.GitHub != nil {
			mu.Lock()
			got = append(got, *m.GitHub)
			mu.Unlock()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	seenContent, seenComment := false, false
	for _, m := range got {
		seenContent = seenContent || m.Entity == "gist"
		seenComment = seenComment || m.Entity == "gist_comment"
		if !strings.HasPrefix(m.Repository, "gist:") {
			t.Fatalf("metadata=%#v", m)
		}
		if strings.Contains(m.Link, "evil.example") || !strings.HasPrefix(m.Link, "https://127.0.0.1:") {
			t.Fatalf("untrusted link: %s", m.Link)
		}
	}
	if !seenContent || !seenComment {
		t.Fatalf("metadata=%#v", got)
	}
	state, err := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if err != nil {
		t.Fatal(err)
	}
	if state.Surfaces["gist-history"]["abc123"].Mode != githubScanModeHistory || state.Surfaces["gist-comments"]["abc123"].IssueComments["1"].UpdatedAt == "" || state.Surfaces["gist-comments"]["abc123"].IssueComments["2"].UpdatedAt == "" {
		t.Fatalf("state=%#v", state.Surfaces)
	}
	cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
	delete(cfg, configKeyIncrementalNextState)
	got = nil
	if err := scanGitHub(context.Background(), cfg, func(_ []byte, m sources.Metadata) error {
		if m.GitHub != nil {
			got = append(got, *m.GitHub)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unchanged gist re-emitted: %#v", got)
	}
}

func TestGitHubAuthenticatedGistPagination(t *testing.T) {
	var calls int
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, []githubGistRef{})
			return
		}
		w.Header().Set("Link", "<"+srv.URL+"/gists?page=2>; rel=\"next\"")
		writeJSON(t, w, []githubGistRef{})
	}))
	t.Cleanup(srv.Close)
	if err := scanGitHub(context.Background(), Config{"token": "x", "api_base": srv.URL, "include_authenticated_gists": "true"}, func([]byte, sources.Metadata) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}
