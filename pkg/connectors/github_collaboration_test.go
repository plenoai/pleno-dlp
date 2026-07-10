package connectors

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubIssuesPaginationMetadataAndIncremental(t *testing.T) {
	var updated atomic.Value
	updated.Store("2026-07-09T00:00:00Z")
	var body atomic.Value
	body.Store("github_pat_11ISSUE__abcdefghijklmnopqrstuvwxyz0123456789")
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("since"); got != "2026-07-01T00:00:00Z" {
			t.Errorf("since = %q", got)
		}
		if r.URL.Query().Get("page") == "2" {
			writeJSON(t, w, []githubIssue{{Number: 2, Title: "second", Body: body.Load().(string), UpdatedAt: updated.Load().(string), HTMLURL: "https://github.test/acme/repo/issues/2"}})
			return
		}
		w.Header().Set("Link", fmt.Sprintf("<%s/repos/acme/repo/issues?page=2&since=2026-07-01T00%%3A00%%3A00Z>; rel=\"next\"", srv.URL))
		writeJSON(t, w, []githubIssue{{Number: 1, Title: "PR-shaped issue", PullRequest: &struct{}{}, UpdatedAt: updated.Load().(string)}})
	}))
	t.Cleanup(srv.Close)
	repo := githubRepoRef{Name: "repo"}
	repo.Owner.Login = "acme"
	cli := newGitHubClient(srv.URL, staticGitHubToken("test"))
	next := githubRepoIncrementalState{}
	var parts []string
	emit := func(data []byte, meta sources.Metadata) error {
		parts = append(parts, meta.GitHub.Part+":"+string(data)+":"+meta.GitHub.Entity)
		return nil
	}
	if err := scanGitHubIssuesIncremental(context.Background(), cli, repo, githubRepoIncrementalState{}, &next, "2026-07-01T00:00:00Z", emit); err != nil {
		t.Fatal(err)
	}
	sort.Strings(parts)
	if got := strings.Join(parts, ","); !strings.Contains(got, "body:github_pat_11ISSUE__") || !strings.Contains(got, "title:second:issue") {
		t.Fatalf("parts = %q", got)
	}
	if next.Issues["2"].UpdatedAt == "" || len(next.Issues) != 1 {
		t.Fatalf("issue state = %#v", next.Issues)
	}
	parts = nil
	second := githubRepoIncrementalState{}
	if err := scanGitHubIssuesIncremental(context.Background(), cli, repo, next, &second, "2026-07-01T00:00:00Z", emit); err != nil {
		t.Fatal(err)
	}
	if len(parts) != 0 {
		t.Fatalf("unchanged issue re-emitted: %v", parts)
	}
	updated.Store("2026-07-10T00:00:00Z")
	body.Store("github_pat_11BODYNEW_abcdefghijklmnopqrstuvwxyz0123456789")
	parts = nil
	third := githubRepoIncrementalState{}
	if err := scanGitHubIssuesIncremental(context.Background(), cli, repo, second, &third, "2026-07-01T00:00:00Z", emit); err != nil {
		t.Fatal(err)
	}
	if len(parts) != 1 || !strings.HasPrefix(parts[0], "body:") {
		t.Fatalf("body-only update emitted %v", parts)
	}
}

func TestGitHubHistoryFailureStillScansRESTSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/repo":
			ref := githubRepoRef{Name: "repo", Visibility: "private"}
			ref.Owner.Login = "acme"
			writeJSON(t, w, ref)
		case "/repos/acme/repo/issues":
			writeJSON(t, w, []githubIssue{{Number: 1, Body: "rest-surface-secret", UpdatedAt: "2026-07-10T00:00:00Z"}})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	var got []string
	err := scanGitHub(context.Background(), Config{"token": "x", "repo": "acme/repo", "api_base": srv.URL, "clone_url_template": filepath.Join(t.TempDir(), "missing"), "include_issues": "true"}, func(data []byte, _ sources.Metadata) error { got = append(got, string(data)); return nil })
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || !slices.Contains(got, "rest-surface-secret") {
		t.Fatalf("err=%v emitted=%v", err, got)
	}
}

func TestGitHubPullRequestsTimeframeAndRateLimit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		writeJSON(t, w, []githubPullRequest{
			{Number: 3, Title: "new", Body: "github_pat_11PULL___abcdefghijklmnopqrstuvwxyz0123456789", UpdatedAt: "2026-07-09T00:00:00Z", HTMLURL: "https://github.test/acme/repo/pull/3"},
			{Number: 2, Title: "old", Body: "old-secret", UpdatedAt: "2026-06-01T00:00:00Z"},
		})
	}))
	t.Cleanup(srv.Close)
	repo := githubRepoRef{Name: "repo"}
	repo.Owner.Login = "acme"
	cli := newGitHubClient(srv.URL, staticGitHubToken("test"))
	cli.testSleep = func(time.Duration) {}
	next := githubRepoIncrementalState{}
	var got []string
	err := scanGitHubPullRequestsIncremental(context.Background(), cli, repo, githubRepoIncrementalState{}, &next, "2026-07-01T00:00:00Z", func(data []byte, meta sources.Metadata) error {
		got = append(got, meta.GitHub.Part+":"+string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || len(next.PullRequests) != 1 || len(got) != 2 {
		t.Fatalf("calls=%d state=%v parts=%v", calls.Load(), next.PullRequests, got)
	}
}

func TestGitHubCollaborationSince(t *testing.T) {
	now := time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)
	got, err := githubCollaborationSince(Config{"collab_timeframe_days": "10"}, now)
	if err != nil || got != "2026-06-30T00:00:00Z" {
		t.Fatalf("since=%q err=%v", got, err)
	}
}

func TestGitHubCommentTimeframeRetainsPreviousCursors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(t, w, []githubIssueComment{})
	}))
	t.Cleanup(srv.Close)
	repo := githubRepoRef{Name: "repo"}
	repo.Owner.Login = "acme"
	prev := githubRepoIncrementalState{IssueComments: map[string]githubCommentIncrementalState{
		"old": {UpdatedAt: "2025-01-01T00:00:00Z"},
	}}
	next := githubRepoIncrementalState{}
	if err := scanGitHubIssueCommentsIncremental(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("test")), repo, prev, true, &next, "2026-07-01T00:00:00Z", func([]byte, sources.Metadata) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if next.IssueComments["old"].UpdatedAt == "" {
		t.Fatal("timeframe-filtered scan dropped previous comment cursor")
	}
}

func TestGitHubPullRequestTimeframeEarlyStopAndMixedOrderDefense(t *testing.T) {
	ref := githubRepoRef{Name: "widget"}
	ref.Owner.Login = "acme"
	t.Run("ordered old page stops", func(t *testing.T) {
		calls := 0
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls > 1 {
				t.Fatal("followed old page")
			}
			w.Header().Set("Link", fmt.Sprintf("<%s/repos/acme/widget/pulls?page=2>; rel=\"next\"", srv.URL))
			writeJSON(t, w, []githubPullRequest{{Number: 1, UpdatedAt: "2026-01-01T00:00:00Z"}})
		}))
		defer srv.Close()
		err := scanGitHubPullRequestsIncremental(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("x")), ref, githubRepoIncrementalState{}, &githubRepoIncrementalState{}, "2026-07-01T00:00:00Z", func([]byte, sources.Metadata) error { return nil })
		if err != nil || calls != 1 {
			t.Fatalf("calls=%d err=%v", calls, err)
		}
	})
	t.Run("mixed order continues", func(t *testing.T) {
		calls, emitted := 0, 0
		var srv *httptest.Server
		srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				w.Header().Set("Link", fmt.Sprintf("<%s/repos/acme/widget/pulls?page=2>; rel=\"next\"", srv.URL))
				writeJSON(t, w, []githubPullRequest{{Number: 1, UpdatedAt: "2026-01-01T00:00:00Z"}, {Number: 2, UpdatedAt: "2026-08-01T00:00:00Z"}})
				return
			}
			writeJSON(t, w, []githubPullRequest{{Number: 3, Title: "recent", UpdatedAt: "2026-08-02T00:00:00Z"}})
		}))
		defer srv.Close()
		err := scanGitHubPullRequestsIncremental(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("x")), ref, githubRepoIncrementalState{}, &githubRepoIncrementalState{}, "2026-07-01T00:00:00Z", func([]byte, sources.Metadata) error { emitted++; return nil })
		if err != nil || calls != 2 || emitted == 0 {
			t.Fatalf("calls=%d emitted=%d err=%v", calls, emitted, err)
		}
	})
}
