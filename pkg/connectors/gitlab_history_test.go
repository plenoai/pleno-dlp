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

func TestGitLabHistoryAndSnippetsIncremental(t *testing.T) {
	repoDir, commit := newTestGitRepo(t)
	commit("OLD=gl-history-1\n")
	var mu sync.Mutex
	snippetUpdated := "2026-01-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/projects/acme/widget", "/projects/acme%2Fwidget":
			writeJSON(t, w, gitlabProjectRef{ID: 1, PathWithNS: "acme/widget", DefaultBranch: "main", HTTPURLToRepo: repoDir})
		case "/projects/1/repository/tree":
			writeJSON(t, w, []gitlabTreeEntry{})
		case "/projects/1/snippets":
			writeJSON(t, w, []gitlabSnippet{{ID: 5, Title: "proj", FileName: "a.sh", UpdatedAt: snippetUpdated}})
		case "/projects/1/snippets/5/raw":
			_, _ = w.Write([]byte("proj-snippet-body"))
		case "/snippets":
			writeJSON(t, w, []gitlabSnippet{{ID: 9, Title: "mine", FileName: "b.txt", UpdatedAt: "2026-01-01T00:00:00Z"}})
		case "/snippets/9/raw":
			_, _ = w.Write([]byte("personal-snippet-body"))
		default:
			t.Errorf("unexpected GitLab API path: %s", r.URL.String())
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{"token": "glpat-test", "project": "acme/widget", "api_base": srv.URL, "history": "true", "include_snippets": "true"}
	run := func() []string {
		t.Helper()
		var got []string
		var gotMu sync.Mutex
		if err := scanGitLab(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
			gotMu.Lock()
			defer gotMu.Unlock()
			if meta.Forge != nil && (meta.Forge.Provider != "gitlab" || meta.Forge.Repository != "acme/widget" || meta.Forge.Commit == "") {
				t.Errorf("bad forge meta %+v", meta.Forge)
			}
			got = append(got, string(data))
			return nil
		}); err != nil {
			t.Fatalf("scanGitLab: %v", err)
		}
		cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
		sort.Strings(got)
		return got
	}
	first := strings.Join(run(), "|")
	for _, want := range []string{"gl-history-1", "proj-snippet-body", "personal-snippet-body"} {
		if !strings.Contains(first, want) {
			t.Fatalf("first scan missing %q: %s", want, first)
		}
	}

	commit("NEW=gl-history-2\n")
	mu.Lock()
	snippetUpdated = "2026-02-01T00:00:00Z"
	mu.Unlock()
	second := strings.Join(run(), "|")
	if !strings.Contains(second, "gl-history-2") || !strings.Contains(second, "proj-snippet-body") {
		t.Fatalf("second scan missing changes: %s", second)
	}
	if strings.Contains(second, "gl-history-1") || strings.Contains(second, "personal-snippet-body") {
		t.Fatalf("second scan re-emitted unchanged content: %s", second)
	}
}

func TestGitLabFingerprintOptsOutWithHistoryOrSnippets(t *testing.T) {
	for _, k := range []string{"history", "include_snippets"} {
		fp, err := fingerprintGitLab(context.Background(), Config{"token": "t", "project": "a/b", "api_base": "https://gitlab.example.com/api/v4", k: "true"})
		if err != nil || fp != "" {
			t.Fatalf("%s: want empty fingerprint without network calls, got %q, %v", k, fp, err)
		}
	}
}
