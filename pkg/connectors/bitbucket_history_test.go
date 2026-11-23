package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestBitbucketHistoryAndSnippetsIncremental(t *testing.T) {
	repoDir, commit := newTestGitRepo(t)
	commit("OLD=bb-history-1\n")
	var mu sync.Mutex
	snippetUpdated := "2026-01-01T00:00:00Z"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer bb-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/2.0/repositories/acme/widget":
			repo := bitbucketRepo("acme", "widget", "main")
			repo.Links.Clone = append(repo.Links.Clone, struct {
				Name string `json:"name"`
				Href string `json:"href"`
			}{Name: "https", Href: repoDir})
			writeJSON(t, w, repo)
		case "/2.0/repositories/acme/widget/src/main/":
			writeJSON(t, w, bitbucketPaginatedSrc{})
		case "/2.0/snippets/acme":
			if r.URL.Query().Get("page") == "" {
				writeJSON(t, w, map[string]any{"values": []any{map[string]any{"id": 7, "title": "a", "updated_on": snippetUpdated}}, "next": srv.URL + "/2.0/snippets/acme?page=2"})
				return
			}
			writeJSON(t, w, map[string]any{"values": []any{map[string]any{"id": "kX9", "title": "b", "updated_on": "2026-01-01T00:00:00Z"}}})
		case "/2.0/snippets/acme/7":
			writeJSON(t, w, map[string]any{"id": 7, "files": map[string]any{"run.sh": map[string]any{"links": map[string]any{"self": map[string]any{"href": srv.URL + "/2.0/snippets/acme/7/files/run.sh"}}}}})
		case "/2.0/snippets/acme/7/files/run.sh":
			_, _ = w.Write([]byte("snippet-7-body"))
		case "/2.0/snippets/acme/kX9":
			writeJSON(t, w, map[string]any{"id": "kX9", "files": map[string]any{"n.txt": map[string]any{}}})
		case "/2.0/snippets/acme/kX9/files/n.txt":
			_, _ = w.Write([]byte("snippet-kX9-body"))
		default:
			t.Errorf("unexpected Bitbucket API path: %s", r.URL.String())
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	// api_base with the documented /2.0 suffix must not double the prefix.
	cfg := Config{"token": "bb-test", "repo": "acme/widget", "api_base": srv.URL + "/2.0", "history": "true", "include_snippets": "true"}
	run := func() string {
		t.Helper()
		var got []string
		var gotMu sync.Mutex
		if err := scanBitbucket(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
			gotMu.Lock()
			defer gotMu.Unlock()
			if meta.Forge != nil && (meta.Forge.Provider != "bitbucket" || meta.Forge.Repository != "acme/widget") {
				t.Errorf("bad forge meta %+v", meta.Forge)
			}
			got = append(got, string(data))
			return nil
		}); err != nil {
			t.Fatalf("scanBitbucket: %v", err)
		}
		cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
		sort.Strings(got)
		return strings.Join(got, "|")
	}
	first := run()
	for _, want := range []string{"bb-history-1", "snippet-7-body", "snippet-kX9-body"} {
		if !strings.Contains(first, want) {
			t.Fatalf("first scan missing %q: %s", want, first)
		}
	}
	commit("NEW=bb-history-2\n")
	mu.Lock()
	snippetUpdated = "2026-02-01T00:00:00Z"
	mu.Unlock()
	second := run()
	if !strings.Contains(second, "bb-history-2") || !strings.Contains(second, "snippet-7-body") {
		t.Fatalf("second scan missing changes: %s", second)
	}
	if strings.Contains(second, "bb-history-1") || strings.Contains(second, "snippet-kX9-body") {
		t.Fatalf("second scan re-emitted unchanged content: %s", second)
	}
}

func TestBitbucketRefusesForeignNextLink(t *testing.T) {
	var leaked bool
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = leaked || r.Header.Get("Authorization") != ""
	}))
	defer evil.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, map[string]any{"values": []any{}, "next": evil.URL + "/2.0/repositories/acme?page=2"})
	}))
	defer srv.Close()
	err := scanBitbucket(context.Background(), Config{"token": "bb-test", "workspace": "acme", "api_base": srv.URL}, func([]byte, sources.Metadata) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "foreign origin") {
		t.Fatalf("want foreign-origin error, got %v", err)
	}
	if leaked {
		t.Fatal("credentials sent to foreign next link")
	}
}

func TestBitbucketHTTPSCloneURLStripsUserinfo(t *testing.T) {
	var r bitbucketRepoRef
	r.Links.Clone = append(r.Links.Clone, struct {
		Name string `json:"name"`
		Href string `json:"href"`
	}{Name: "ssh", Href: "git@bitbucket.org:acme/w.git"}, struct {
		Name string `json:"name"`
		Href string `json:"href"`
	}{Name: "https", Href: "https://alice@bitbucket.org/acme/w.git"})
	if got := r.httpsCloneURL(); got != "https://bitbucket.org/acme/w.git" {
		t.Fatalf("httpsCloneURL = %q", got)
	}
}

func TestBitbucketFingerprintOptsOutWithHistoryOrSnippets(t *testing.T) {
	for _, k := range []string{"history", "include_snippets"} {
		fp, err := fingerprintBitbucket(context.Background(), Config{"token": "t", "repo": "a/b", "api_base": "https://api.bitbucket.example/2.0", k: "true"})
		if err != nil || fp != "" {
			t.Fatalf("%s: want empty fingerprint, got %q, %v", k, fp, err)
		}
	}
}
