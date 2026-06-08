package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
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

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("encode response: %v", err)
	}
}
