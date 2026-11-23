package connectors

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubUserEventsEmitsPayloadText(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/users/alice/events/public" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", "<"+srv.URL+"/users/alice/events/public?per_page=100&page=2>; rel=\"next\"")
			_, _ = w.Write([]byte(`[{"id":"1","type":"PushEvent","repo":{"name":"alice/x"},"payload":{"commits":[{"sha":"abc","message":"add key AKIAEXAMPLE","url":"https://api.github.com/x"}]}}]`))
		case r.URL.Path == "/users/alice/events/public":
			_, _ = w.Write([]byte(`[{"id":"2","type":"IssueCommentEvent","repo":{"name":"bob/y"},"payload":{"comment":{"body":"token=hunter2"}}},{"id":"3","type":"WatchEvent","repo":{"name":"bob/y"},"payload":{}}]`))
		case r.URL.Path == "/users/broken/events/public":
			http.Error(w, "gone", http.StatusNotFound)
		default:
			t.Errorf("unexpected %s", r.URL)
		}
	}))
	defer srv.Close()
	var got []string
	err := scanGitHubUserEvents(context.Background(), newGitHubClient(srv.URL, nil), []string{"alice", "broken"}, time.Time{}, func(data []byte, meta sources.Metadata) error {
		g := meta.GitHub
		got = append(got, g.Repository+"|"+g.Path+"|"+g.Part+"|"+string(data))
		return nil
	})
	var de *engine.DegradedError
	if !errors.As(err, &de) || de.Total != 1 || de.Failures[0].Source != "github:events/broken" {
		t.Fatalf("want degraded broken feed, got %v", err)
	}
	want := "alice/x|event:1|PushEvent|add key AKIAEXAMPLE;bob/y|event:2|IssueCommentEvent|token=hunter2"
	if strings.Join(got, ";") != want {
		t.Fatalf("got %q", got)
	}
}

func TestGitHubUserEventsRefusesForeignNextLink(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", "<https://evil.test/users/alice/events/public?page=2>; rel=\"next\"")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	err := scanGitHubUserEvents(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("t")), []string{"alice"}, time.Time{}, func([]byte, sources.Metadata) error { return nil })
	var de *engine.DegradedError
	if !errors.As(err, &de) {
		t.Fatalf("want degraded for foreign next link, got %v", err)
	}
}

func TestGitHubScanUserReposAndValidation(t *testing.T) {
	ctx := context.Background()
	noop := func([]byte, sources.Metadata) error { return nil }
	for _, cfg := range []Config{
		{"token": "x", "user": "a", "org": "o"},
		{"token": "x", "user": "a", "repo": "o/r"},
		{"token": "x", "org": "o", "include_user_events": "true"},
	} {
		if err := scanGitHub(ctx, cfg, noop); err == nil {
			t.Errorf("scanGitHub(%v) accepted invalid config", cfg)
		}
	}

	fixture := buildHFFixtureRepo(t)
	var listed []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		listed = append(listed, r.URL.Path)
		if r.URL.Path == "/users/alice/repos" {
			_, _ = w.Write([]byte(`[{"name":"r1","full_name":"alice/r1","owner":{"login":"alice"},"default_branch":"main"}]`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	var files []string
	err := scanGitHub(ctx, Config{"token": "x", "user": "alice", "api_base": srv.URL, "clone_url_template": filepath.Clean(fixture), "repo_concurrency": "1"}, func(_ []byte, meta sources.Metadata) error {
		if meta.GitHub != nil {
			files = append(files, meta.GitHub.Repository+"/"+meta.GitHub.File)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanGitHub user: %v", err)
	}
	if len(files) == 0 || !strings.Contains(strings.Join(files, ","), "secret.txt") {
		t.Fatalf("no user repo content emitted: %v (requests %v)", files, listed)
	}
}

func TestGitHubScopeFingerprintStableWithoutUser(t *testing.T) {
	a := githubScopeFingerprint(Config{"org": "o"})
	if a != githubScopeFingerprint(Config{"org": "o", "user": ""}) {
		t.Fatal("empty user changed scope fingerprint")
	}
	if a == githubScopeFingerprint(Config{"user": "o"}) {
		t.Fatal("user scope collides with org scope")
	}
}

func TestGitHubUserEventsLookbackStopsAtOlderEvents(t *testing.T) {
	now := time.Now().UTC()
	pages := 0
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages++
		w.Header().Set("Link", "<"+srv.URL+"/users/a/events/public?page=2>; rel=\"next\"")
		_, _ = w.Write([]byte(`[{"id":"new","type":"PushEvent","created_at":"` + now.Format(time.RFC3339) + `","repo":{"name":"a/r"},"payload":{"commits":[{"message":"fresh"}]}},{"id":"old","type":"PushEvent","created_at":"` + now.Add(-48*time.Hour).Format(time.RFC3339) + `","repo":{"name":"a/r"},"payload":{"commits":[{"message":"stale"}]}}]`))
	}))
	defer srv.Close()
	var got []string
	if err := scanGitHubUserEvents(context.Background(), newGitHubClient(srv.URL, nil), []string{"a"}, now.Add(-time.Hour), func(d []byte, _ sources.Metadata) error {
		got = append(got, string(d))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "fresh" || pages != 1 {
		t.Fatalf("got %v after %d pages", got, pages)
	}
}
