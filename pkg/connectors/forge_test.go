package connectors

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestForgeConnectorRegistrations(t *testing.T) {
	cases := map[string]sources.SourceType{
		"forgejo":   sources.SourceForgejo,
		"gitea":     sources.SourceGitea,
		"gogs":      sources.SourceGogs,
		"gitbucket": sources.SourceGitbucket,
		"codeberg":  sources.SourceCodeberg,
		"onedev":    sources.SourceOneDev,
		"codebase":  sources.SourceCodebase,
		"pagure":    sources.SourcePagure,
	}
	for name, wantType := range cases {
		conn, ok := Get(name)
		if !ok {
			t.Fatalf("Get(%q) ok = false, want true", name)
		}
		if conn.Scan == nil {
			t.Fatalf("Get(%q).Scan = nil, want scan implementation", name)
		}
		if conn.SourceType != wantType {
			t.Fatalf("Get(%q).SourceType = %s, want %s", name, conn.SourceType, wantType)
		}
	}
}

func TestGiteaCompatibleIncrementalScanEmitsOnlyChangedComments(t *testing.T) {
	comments := []giteaComment{
		{ID: 1, Body: "old secret"},
		{ID: 2, Body: "keep secret"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget/issues/comments" {
			t.Fatalf("unexpected Gitea API path: %s", r.URL.String())
		}
		writeJSON(t, w, comments)
	}))
	defer srv.Close()

	cfg := Config{"token": "gitea-token", "repo": "acme/widget", "api_base": srv.URL}
	var first []string
	if err := scanGiteaCompatible(context.Background(), giteaProvider{name: "gitea", typ: sources.SourceGitea}, cfg, func(data []byte, _ sources.Metadata) error {
		first = append(first, string(data))
		return nil
	}); err != nil {
		t.Fatalf("first scanGiteaCompatible: %v", err)
	}
	if got, want := strings.Join(first, ","), "old secret,keep secret"; got != want {
		t.Fatalf("first emitted %q, want %q", got, want)
	}
	previous := cfg[configKeyIncrementalNextState]
	if previous == "" {
		t.Fatal("first scan did not persist incremental state")
	}
	if !json.Valid([]byte(previous)) {
		t.Fatalf("invalid incremental state: %s", previous)
	}

	comments = []giteaComment{
		{ID: 1, Body: "new secret"},
		{ID: 2, Body: "keep secret"},
	}
	cfg[configKeyIncrementalPreviousState] = previous
	delete(cfg, configKeyIncrementalNextState)
	var second []string
	if err := scanGiteaCompatible(context.Background(), giteaProvider{name: "gitea", typ: sources.SourceGitea}, cfg, func(data []byte, _ sources.Metadata) error {
		second = append(second, string(data))
		return nil
	}); err != nil {
		t.Fatalf("second scanGiteaCompatible: %v", err)
	}
	if got, want := strings.Join(second, ","), "new secret"; got != want {
		t.Fatalf("second emitted %q, want only changed comment %q", got, want)
	}
}

func TestGiteaHistoryWalksCloneIncrementally(t *testing.T) {
	repoDir := t.TempDir()
	repo, err := gogit.PlainInit(repoDir, false)
	if err != nil {
		t.Fatal(err)
	}
	commit := func(content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(repoDir, "cfg.env"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		wt, _ := repo.Worktree()
		if _, err := wt.Add("cfg.env"); err != nil {
			t.Fatal(err)
		}
		sig := &object.Signature{Name: "t", Email: "t@example.com", When: time.Now()}
		if _, err := wt.Commit(content, &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
			t.Fatal(err)
		}
	}
	commit("FIRST=history-secret-1\n")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, []giteaComment{})
	}))
	defer srv.Close()
	provider := giteaProvider{name: "gitea", typ: sources.SourceGitea}
	cfg := Config{"token": "gitea-token", "repo": "acme/widget", "api_base": srv.URL + "/api/v1", "history": "true", "clone_url": repoDir}
	run := func() []string {
		t.Helper()
		var got []string
		tokenless := Config{}
		for k, v := range cfg {
			tokenless[k] = v
		}
		if err := scanGiteaCompatible(context.Background(), provider, tokenless, func(data []byte, meta sources.Metadata) error {
			if meta.Forge == nil || meta.Forge.Commit == "" || meta.Forge.Repository != "acme/widget" {
				t.Fatalf("bad forge meta: %+v", meta.Forge)
			}
			got = append(got, string(data))
			return nil
		}); err != nil {
			t.Fatalf("scan: %v", err)
		}
		cfg[configKeyIncrementalPreviousState] = tokenless[configKeyIncrementalNextState]
		return got
	}
	first := run()
	if !strings.Contains(strings.Join(first, ""), "history-secret-1") {
		t.Fatalf("first scan missed history: %q", first)
	}
	commit("SECOND=history-secret-2\n")
	second := strings.Join(run(), "")
	if !strings.Contains(second, "history-secret-2") || strings.Contains(second, "history-secret-1") {
		t.Fatalf("incremental scan = %q, want only the new commit", second)
	}
}

func TestGiteaCloneURL(t *testing.T) {
	cases := map[string]string{
		"https://git.example.com/api/v1":       "https://git.example.com/a/b.git",
		"https://example.com/gitea/api/v1/":    "https://example.com/gitea/a/b.git",
		"https://gitbucket.example.com/api/v3": "https://gitbucket.example.com/a/b.git",
	}
	for in, want := range cases {
		if got := giteaCloneURL(in, "a", "b"); got != want {
			t.Errorf("giteaCloneURL(%q) = %q, want %q", in, got, want)
		}
	}
}
