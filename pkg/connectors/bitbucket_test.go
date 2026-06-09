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

func TestBitbucketFingerprintUsesMetadataWithoutFetchingFiles(t *testing.T) {
	var rawCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2.0/repositories/acme/widget":
			writeJSON(t, w, bitbucketRepo("acme", "widget", "main"))
		case "/2.0/repositories/acme/widget/src/main/":
			writeJSON(t, w, bitbucketPaginatedSrc{Values: []bitbucketSrcEntry{
				bitbucketEntry("app.go", "commit_file", 12, "hash-app"),
				bitbucketEntry("README.md", "commit_file", 6, "hash-readme"),
			}})
		case "/2.0/repositories/acme/widget/src/main/app.go", "/2.0/repositories/acme/widget/src/main/README.md":
			rawCalls++
			t.Errorf("fingerprint must not fetch file content: %s", r.URL.Path)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("unexpected Bitbucket API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	got, err := fingerprintBitbucket(context.Background(), Config{
		"token":    "bb-test",
		"repo":     "acme/widget",
		"api_base": srv.URL,
	})
	if err != nil {
		t.Fatalf("fingerprintBitbucket: %v", err)
	}
	if got == "" {
		t.Fatal("fingerprint must not be empty")
	}
	if rawCalls != 0 {
		t.Fatalf("rawCalls = %d, want 0", rawCalls)
	}
}

func TestBitbucketIncrementalScanEmitsOnlyChangedFiles(t *testing.T) {
	entries := []bitbucketSrcEntry{
		bitbucketEntry("app.go", "commit_file", 12, "hash-app"),
		bitbucketEntry("README.md", "commit_file", 6, "hash-readme"),
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/2.0/repositories/acme/widget":
			writeJSON(t, w, bitbucketRepo("acme", "widget", "main"))
		case "/2.0/repositories/acme/widget/src/main/":
			writeJSON(t, w, bitbucketPaginatedSrc{Values: entries})
		case "/2.0/repositories/acme/widget/src/main/app.go":
			_, _ = w.Write([]byte("app-secret"))
		case "/2.0/repositories/acme/widget/src/main/README.md":
			if containsBitbucketEntry(entries, "README.md", "hash-readme-v2") {
				_, _ = w.Write([]byte("readme-secret-v2"))
				return
			}
			_, _ = w.Write([]byte("readme-secret"))
		default:
			t.Fatalf("unexpected Bitbucket API path: %s", r.URL.String())
		}
	}))
	t.Cleanup(srv.Close)

	cfg := Config{"token": "bb-test", "repo": "acme/widget", "api_base": srv.URL}
	var first []string
	var firstMu sync.Mutex
	if err := scanBitbucket(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		firstMu.Lock()
		defer firstMu.Unlock()
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanBitbucket: %v", err)
	}
	sort.Strings(first)
	if got, want := strings.Join(first, ","), "app-secret,readme-secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental source state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	entries = []bitbucketSrcEntry{
		bitbucketEntry("app.go", "commit_file", 12, "hash-app"),
		bitbucketEntry("README.md", "commit_file", 6, "hash-readme-v2"),
	}
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)

	var second []string
	var secondMu sync.Mutex
	if err := scanBitbucket(context.Background(), cfg, func(data []byte, _ sources.Metadata) error {
		secondMu.Lock()
		defer secondMu.Unlock()
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanBitbucket: %v", err)
	}
	if got, want := strings.Join(second, ","), "readme-secret-v2"; got != want {
		t.Fatalf("second emitted %q, want only changed file %q", got, want)
	}
}

func bitbucketRepo(workspace, name, branch string) bitbucketRepoRef {
	var repo bitbucketRepoRef
	repo.FullName = workspace + "/" + name
	repo.Name = name
	repo.Workspace.Slug = workspace
	repo.MainBranch.Name = branch
	return repo
}

func bitbucketEntry(path, typ string, size int64, hash string) bitbucketSrcEntry {
	var entry bitbucketSrcEntry
	entry.Path = path
	entry.Type = typ
	entry.Size = size
	entry.Commit.Hash = hash
	return entry
}

func containsBitbucketEntry(entries []bitbucketSrcEntry, path, hash string) bool {
	for _, entry := range entries {
		if entry.Path == path && entry.Commit.Hash == hash {
			return true
		}
	}
	return false
}
