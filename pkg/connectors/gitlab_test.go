package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitLabFingerprintUsesMetadataWithoutFetchingBlobs(t *testing.T) {
	var rawCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/projects/acme/widget", "/projects/acme%2Fwidget":
			writeJSON(t, w, gitlabProjectRef{ID: 1, PathWithNS: "acme/widget", DefaultBranch: "main"})
		case "/projects/1/repository/tree":
			writeJSON(t, w, []gitlabTreeEntry{
				{Path: "app.go", Type: "blob", ID: "blob-app"},
				{Path: "README.md", Type: "blob", ID: "blob-readme"},
			})
		case "/projects/1/repository/files/app.go/raw", "/projects/1/repository/files/README.md/raw":
			rawCalls++
			t.Errorf("fingerprint must not fetch raw blob content: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected GitLab API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	got, err := fingerprintGitLab(context.Background(), Config{
		"token":    "glpat-test",
		"project":  "acme/widget",
		"api_base": srv.URL,
	})
	if err != nil {
		t.Fatalf("fingerprintGitLab: %v", err)
	}
	if got == "" {
		t.Fatal("fingerprint must not be empty")
	}
	if rawCalls != 0 {
		t.Fatalf("rawCalls = %d, want 0", rawCalls)
	}
}

func TestGitLabIncrementalScanEmitsOnlyChangedResources(t *testing.T) {
	treeEntries := []gitlabTreeEntry{
		{Path: "app.go", Type: "blob", ID: "blob-app"},
		{Path: "README.md", Type: "blob", ID: "blob-readme"},
	}
	noteUpdated := "2026-06-09T00:00:00Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/projects/acme/widget", "/projects/acme%2Fwidget":
			writeJSON(t, w, gitlabProjectRef{ID: 1, PathWithNS: "acme/widget", DefaultBranch: "main"})
		case "/projects/1/repository/tree":
			writeJSON(t, w, treeEntries)
		case "/projects/1/repository/files/app.go/raw":
			_, _ = w.Write([]byte("app-secret"))
		case "/projects/1/repository/files/README.md/raw":
			if containsBlob(treeEntries, "README.md", "blob-readme-v2") {
				_, _ = w.Write([]byte("readme-secret-v2"))
				return
			}
			_, _ = w.Write([]byte("readme-secret"))
		case "/projects/1/merge_requests":
			writeJSON(t, w, []gitlabMergeRequestRef{{IID: 7, Title: "MR"}})
		case "/projects/1/merge_requests/7/notes":
			writeJSON(t, w, []gitlabNote{{ID: 101, Body: "note-secret", UpdatedAt: noteUpdated}})
		case "/projects/1/merge_requests/7/discussions":
			writeJSON(t, w, []gitlabDiscussion{})
		default:
			t.Fatalf("unexpected GitLab API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":            "glpat-test",
		"project":          "acme/widget",
		"api_base":         srv.URL,
		"include_comments": "true",
	}
	var first []string
	var firstMu sync.Mutex
	if err := scanGitLab(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		firstMu.Lock()
		defer firstMu.Unlock()
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanGitLab: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "app-secret,note-secret,readme-secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental source state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	treeEntries = []gitlabTreeEntry{
		{Path: "app.go", Type: "blob", ID: "blob-app"},
		{Path: "README.md", Type: "blob", ID: "blob-readme-v2"},
	}
	noteUpdated = "2026-06-09T01:00:00Z"
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)

	var second []string
	var secondMu sync.Mutex
	if err := scanGitLab(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		secondMu.Lock()
		defer secondMu.Unlock()
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanGitLab: %v", err)
	}
	sort.Strings(second)
	if got, want := strings.Join(second, ","), "note-secret,readme-secret-v2"; got != want {
		t.Fatalf("second emitted %q, want only changed resources %q", got, want)
	}
}

func containsBlob(entries []gitlabTreeEntry, path, id string) bool {
	for _, entry := range entries {
		if entry.Path == path && entry.ID == id {
			return true
		}
	}
	return false
}
