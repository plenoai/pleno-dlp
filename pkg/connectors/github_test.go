package connectors

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

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
		"scan_mode":        "tree",
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

	cfg := Config{"token": "ghp_test", "repo": "acme/widget", "api_base": srv.URL, "scan_mode": "tree"}
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
		"scan_mode":        "tree",
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

func TestGitHubAppTokenProviderRefreshesInstallationToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	now := time.Date(2026, 6, 9, 0, 0, 0, 0, time.UTC)
	var tokenCalls int
	var seenAuth []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			tokenCalls++
			if r.Method != http.MethodPost {
				t.Fatalf("token method = %s, want POST", r.Method)
			}
			if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Bearer ") || strings.Count(strings.TrimPrefix(auth, "Bearer "), ".") != 2 {
				t.Fatalf("token request Authorization must be a bearer JWT, got %q", auth)
			}
			writeJSON(t, w, githubAppTokenResp{
				Token:     "installation-token-" + strconv.Itoa(tokenCalls),
				ExpiresAt: now.Add(4 * time.Minute).Format(time.RFC3339),
			})
		case "/rate_limit":
			seenAuth = append(seenAuth, r.Header.Get("Authorization"))
			writeJSON(t, w, map[string]any{"ok": true})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)

	auth, err := newGitHubAppTokenProvider(Config{
		"api_base":            srv.URL,
		"app_id":              "123",
		"app_installation_id": "42",
		"app_private_key":     string(keyPEM),
	})
	if err != nil {
		t.Fatalf("newGitHubAppTokenProvider: %v", err)
	}
	auth.now = func() time.Time { return now }
	cli := newGitHubClient(srv.URL, auth)
	for i := 0; i < 2; i++ {
		resp, err := cli.do(context.Background(), http.MethodGet, "/rate_limit", nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		_ = resp.Body.Close()
	}
	if tokenCalls != 2 {
		t.Fatalf("tokenCalls = %d, want 2 refreshes for near-expiry tokens", tokenCalls)
	}
	if got, want := strings.Join(seenAuth, ","), "Bearer installation-token-1,Bearer installation-token-2"; got != want {
		t.Fatalf("seen auth = %q, want %q", got, want)
	}
}

func TestGitHubAuthProviderRejectsAmbiguousAuth(t *testing.T) {
	_, err := newGitHubAuthProvider(Config{
		"token":               "ghp_test",
		"app_id":              "123",
		"app_installation_id": "42",
		"app_private_key":     "pem",
	})
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutually exclusive auth error, got %v", err)
	}
}

func TestNormalizePEMNewlines(t *testing.T) {
	got := normalizePEMNewlines(`-----BEGIN KEY-----\nabc\n-----END KEY-----`)
	if !strings.Contains(got, "\nabc\n") {
		t.Fatalf("escaped PEM newlines were not normalized: %q", got)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil && !strings.Contains(err.Error(), "broken pipe") {
		t.Fatalf("encode response: %v", err)
	}
}
