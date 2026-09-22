package connectors

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestDeriveWikiCloneURL(t *testing.T) {
	for _, tc := range []struct{ base, want string }{
		{"https://api.github.com", "https://github.com/acme/repo.wiki.git"},
		{"https://ghe.example/api/v3", "https://ghe.example/acme/repo.wiki.git"},
	} {
		got, err := deriveWikiCloneURL(tc.base, "acme", "repo", "")
		if err != nil || got != tc.want {
			t.Fatalf("deriveWikiCloneURL(%q) = %q, %v; want %q", tc.base, got, err, tc.want)
		}
	}
	exact := "/tmp/acme/repo.wiki.git"
	if got, err := deriveWikiCloneURL("https://api.github.com", "acme", "repo", exact); err != nil || got != exact {
		t.Fatalf("explicit final wiki template doubled suffix: %q %v", got, err)
	}
}

func TestGitHubWikiSafeLinks(t *testing.T) {
	for _, tc := range []struct{ host, path, want string }{
		{"github.com", "Run Book.md", "https://github.com/acme/repo/wiki/Run%20Book"},
		{"ghe.example", "日本語.md", "https://ghe.example/acme/repo/wiki/%E6%97%A5%E6%9C%AC%E8%AA%9E"},
		{"github.com", "_Sidebar.md", "https://github.com/acme/repo.wiki/blob/abc/_Sidebar.md"},
		{"github.com", "asset.png", "https://github.com/acme/repo.wiki/blob/abc/asset.png"},
		{"github.com", "bundle.zip!inner.md", "https://github.com/acme/repo.wiki/blob/abc/bundle.zip"},
	} {
		if got := githubWikiLink(tc.host, "acme", "repo", "abc", tc.path, 0); got != tc.want {
			t.Errorf("link(%q)=%q want %q", tc.path, got, tc.want)
		}
	}
}

func TestGoGitCloneSendsPATAndClassifiesAuth(t *testing.T) {
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)
	err := cloneWithGoGit(context.Background(), srv.URL+"/acme/repo.wiki.git", t.TempDir()+"/clone", "pat-secret", io.Discard)
	var cloneErr *githubCloneError
	if !errors.As(err, &cloneErr) || cloneErr.Kind != githubCloneAuth {
		t.Fatalf("error=%v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:pat-secret"))
	if auth != want {
		t.Fatalf("Authorization=%q want %q", auth, want)
	}
	if strings.Contains(err.Error(), "pat-secret") {
		t.Fatal("go-git error leaked PAT")
	}
}

func TestNativeCloneRedactsPATAndClassifiesAuth(t *testing.T) {
	token := "pat-native-secret"
	script := filepath.Join(t.TempDir(), "git")
	body := "#!/bin/sh\necho 'Authentication failed: " + token + "' >&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	err := cloneWithNativeGit(context.Background(), script, "https://github.com/acme/repo.wiki.git", t.TempDir()+"/clone", token, io.Discard)
	var cloneErr *githubCloneError
	if !errors.As(err, &cloneErr) || cloneErr.Kind != githubCloneAuth {
		t.Fatalf("error=%v", err)
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("native error leaked PAT: %v", err)
	}
}

type countingWikiToken struct{ calls int }

func (p *countingWikiToken) Token(context.Context) (string, error) {
	p.calls++
	return "installation-or-pat", nil
}

func TestWikiCloneTokenUsesSharedPATOrAppProvider(t *testing.T) {
	p := &countingWikiToken{}
	got, err := githubCloneToken(context.Background(), p, "https://github.com/acme/repo.wiki.git")
	if err != nil || got != "installation-or-pat" || p.calls != 1 {
		t.Fatalf("token=%q calls=%d err=%v", got, p.calls, err)
	}
}

func TestGitHubWikiDisablesWholeResourceFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ref := githubRepoRef{Name: "repo", HasWiki: true}
		ref.Owner.Login = "acme"
		writeJSON(t, w, ref)
	}))
	t.Cleanup(srv.Close)
	fp, err := fingerprintGitHub(context.Background(), Config{"token": "x", "repo": "acme/repo", "api_base": srv.URL, "include_wikis": "true"})
	if err != nil || fp != "" {
		t.Fatalf("fingerprint=%q err=%v", fp, err)
	}
}

func TestGitHubWikiIndependentUnitMetadataAndState(t *testing.T) {
	mainRepo, _ := buildFixtureRepo(t)
	wikiRepo, _ := buildFixtureRepo(t)
	wikiBase := filepath.Join(t.TempDir(), "repo")
	if err := os.Symlink(wikiRepo, wikiBase+".wiki.git"); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/repo" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		ref := githubRepoRef{Name: "repo", HasWiki: true, Visibility: "private"}
		ref.Owner.Login = "acme"
		writeJSON(t, w, ref)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{
		"token": "ghp_test", "repo": "acme/repo", "api_base": srv.URL,
		"clone_url_template": mainRepo, "wiki_clone_url_template": wikiBase,
		"include_wikis": "true", "repo_concurrency": "2",
	}
	var wikiMetadata []sources.GitHubMeta
	var mu sync.Mutex
	if err := scanGitHub(context.Background(), cfg, func(_ []byte, meta sources.Metadata) error {
		if meta.GitHub != nil && meta.GitHub.Entity == "wiki" {
			mu.Lock()
			wikiMetadata = append(wikiMetadata, *meta.GitHub)
			mu.Unlock()
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(wikiMetadata) == 0 || wikiMetadata[0].Part != "page" || !strings.Contains(wikiMetadata[0].Link, "/acme/repo.wiki/blob/") {
		t.Fatalf("wiki metadata = %#v", wikiMetadata)
	}
	state, err := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if err != nil {
		t.Fatal(err)
	}
	if state.Surfaces["repository-wiki"]["acme/repo"].Mode != githubScanModeHistory || state.Surfaces["repository-history"]["acme/repo"].Mode != githubScanModeHistory {
		t.Fatalf("independent surface state = %#v", state.Surfaces)
	}
}

func TestGitHubDisabledWikiIsNonfatal(t *testing.T) {
	mainRepo, _ := buildFixtureRepo(t)
	hasWiki := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		ref := githubRepoRef{Name: "repo", HasWiki: hasWiki}
		ref.Owner.Login = "acme"
		writeJSON(t, w, ref)
	}))
	t.Cleanup(srv.Close)
	cfg := Config{
		"token": "ghp_test", "repo": "acme/repo", "api_base": srv.URL,
		"clone_url_template": mainRepo, "include_wikis": "true", "repo_concurrency": "2",
	}
	err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
	if err != nil {
		t.Fatalf("disabled wiki must be a nonfatal skip: %v", err)
	}
	hasWiki = true
	cfg["wiki_clone_url_template"] = filepath.Join(t.TempDir(), "missing")
	if err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil }); err != nil {
		t.Fatalf("enabled but missing wiki must be a nonfatal skip: %v", err)
	}
}
