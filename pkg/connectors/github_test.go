package connectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubFingerprintUsesMetadataWithoutFetchingBlobs(t *testing.T) {
	var blobCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widget":
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "main"})
		case "/repos/acme/widget/git/trees/main":
			writeJSON(t, w, githubTreeResp{
				SHA: "tree-sha",
				Tree: []githubTreeNode{
					{Path: "app.go", Type: "blob", SHA: "blob-1", Size: 12},
					{Path: "README.md", Type: "blob", SHA: "blob-2", Size: 34},
				},
			})
		case "/repos/acme/widget/issues/comments":
			writeJSON(t, w, []githubIssueComment{{ID: 101, UpdatedAt: "2026-06-09T00:00:00Z"}})
		case "/repos/acme/widget/pulls/comments":
			writeJSON(t, w, []githubPullReviewComment{{ID: 202, Path: "app.go", Position: 7, UpdatedAt: "2026-06-09T00:00:00Z"}})
		case "/repos/acme/widget/git/blobs/blob-1", "/repos/acme/widget/git/blobs/blob-2":
			blobCalls++
			t.Errorf("fingerprint must not fetch blob content: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected GitHub API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	got, err := fingerprintGitHub(context.Background(), Config{
		"token":            "ghp_test",
		"repo":             "acme/widget",
		"api_base":         srv.URL,
		"include_comments": "true",
	})
	if err != nil {
		t.Fatalf("fingerprintGitHub: %v", err)
	}
	if got == "" {
		t.Fatal("fingerprint must not be empty")
	}
	if blobCalls != 0 {
		t.Fatalf("blobCalls = %d, want 0", blobCalls)
	}
}

func TestGitHubFingerprintChangesWhenTreeChanges(t *testing.T) {
	treeSHA := "tree-a"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widget":
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "main"})
		case "/repos/acme/widget/git/trees/main":
			writeJSON(t, w, githubTreeResp{
				SHA:  treeSHA,
				Tree: []githubTreeNode{{Path: "app.go", Type: "blob", SHA: treeSHA + "-blob", Size: 12}},
			})
		default:
			t.Fatalf("unexpected GitHub API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{"token": "ghp_test", "repo": "acme/widget", "api_base": srv.URL}
	first, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first fingerprintGitHub: %v", err)
	}
	treeSHA = "tree-b"
	second, err := fingerprintGitHub(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second fingerprintGitHub: %v", err)
	}
	if first == second {
		t.Fatalf("fingerprint did not change after tree changed: %s", first)
	}
}

func TestGitHubIncrementalScanEmitsOnlyChangedResources(t *testing.T) {
	treeNodes := []githubTreeNode{
		{Path: "app.go", Type: "blob", SHA: "blob-app", Size: 12},
		{Path: "README.md", Type: "blob", SHA: "blob-readme", Size: 6},
	}
	issueUpdated := "2026-06-09T00:00:00Z"
	pullUpdated := "2026-06-09T00:00:00Z"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/acme/widget":
			writeJSON(t, w, githubRepoRef{Name: "widget", DefaultBranch: "main"})
		case "/repos/acme/widget/git/trees/main":
			writeJSON(t, w, githubTreeResp{SHA: "tree", Tree: treeNodes})
		case "/repos/acme/widget/git/blobs/blob-app":
			writeJSON(t, w, githubBlobResp{SHA: "blob-app", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("app-secret"))})
		case "/repos/acme/widget/git/blobs/blob-readme":
			writeJSON(t, w, githubBlobResp{SHA: "blob-readme", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("readme-secret"))})
		case "/repos/acme/widget/git/blobs/blob-readme-v2":
			writeJSON(t, w, githubBlobResp{SHA: "blob-readme-v2", Encoding: "base64", Content: base64.StdEncoding.EncodeToString([]byte("readme-secret-v2"))})
		case "/repos/acme/widget/issues/comments":
			writeJSON(t, w, []githubIssueComment{{ID: 101, Body: "issue-secret", UpdatedAt: issueUpdated}})
		case "/repos/acme/widget/pulls/comments":
			writeJSON(t, w, []githubPullReviewComment{{ID: 202, Body: "pull-secret", Path: "app.go", Position: 7, UpdatedAt: pullUpdated}})
		default:
			t.Fatalf("unexpected GitHub API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":            "ghp_test",
		"repo":             "acme/widget",
		"api_base":         srv.URL,
		"include_comments": "true",
	}
	var first []string
	var firstMu sync.Mutex
	if err := scanGitHub(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		firstMu.Lock()
		defer firstMu.Unlock()
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanGitHub: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "app-secret,issue-secret,pull-secret,readme-secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental source state")
	}

	treeNodes = []githubTreeNode{
		{Path: "app.go", Type: "blob", SHA: "blob-app", Size: 12},
		{Path: "README.md", Type: "blob", SHA: "blob-readme-v2", Size: 9},
	}
	pullUpdated = "2026-06-09T01:00:00Z"
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)

	var second []string
	var secondMu sync.Mutex
	if err := scanGitHub(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		secondMu.Lock()
		defer secondMu.Unlock()
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanGitHub: %v", err)
	}
	sort.Strings(second)
	if got, want := strings.Join(second, ","), "pull-secret,readme-secret-v2"; got != want {
		t.Fatalf("second emitted %q, want only changed resources %q", got, want)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("encode response: %v", err)
	}
}
