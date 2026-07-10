package connectors

import (
	"archive/zip"
	"bytes"
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
	archivepkg "github.com/plenoai/pleno-dlp/pkg/archive"
	"github.com/plenoai/pleno-dlp/pkg/detectors"
	_ "github.com/plenoai/pleno-dlp/pkg/detectors/all"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/sources/filesystem"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
	stdinsource "github.com/plenoai/pleno-dlp/pkg/sources/stdin"
)

func boundaryRepo(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	wt, _ := repo.Worktree()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = wt.Add(name)
	sig := &object.Signature{Name: "B3", Email: "b3@example.invalid", When: time.Date(2026, 7, 10, 0, 0, 0, 0, time.UTC)}
	if _, err := wt.Commit("fixture", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func collectSourceChunks(t *testing.T, src sources.Source, cfg any) [][]byte {
	t.Helper()
	raw, _ := json.Marshal(cfg)
	if err := src.Init(context.Background(), "b3", 0, 1, false, raw, 1); err != nil {
		t.Fatal(err)
	}
	ch := make(chan *sources.Chunk, 8)
	errCh := make(chan error, 1)
	go func() { errCh <- src.Chunks(context.Background(), ch); close(ch) }()
	var out [][]byte
	for c := range ch {
		out = append(out, append([]byte(nil), c.Data...))
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	return out
}

func assertBoundaryKeyword(t *testing.T, sourceName, detectorName string, chunks [][]byte) {
	t.Helper()
	var d detectors.Detector
	for _, candidate := range detectors.All() {
		if candidate.Type().String() == detectorName {
			d = candidate
			break
		}
	}
	if d == nil {
		t.Fatalf("detector %s not registered", detectorName)
	}
	hits := 0
	for _, chunk := range chunks {
		lower := strings.ToLower(string(chunk))
		for _, keyword := range d.Keywords() {
			if strings.Contains(lower, strings.ToLower(keyword)) {
				hits++
			}
		}
	}
	if hits == 0 {
		t.Fatalf("actual %s emission produced zero %s keyword prefilter hits; chunks=%q keywords=%v", sourceName, detectorName, chunks, d.Keywords())
	}
}

func TestSourceFixtureDetectorKeywordMatrix(t *testing.T) {
	const aws = "aws_access_key_id=AKIA7M4Q2W9R6T3Y8U1I"
	const slack = "slack_token=" + "xoxb" + "-1234567890-1234567890123-a1B2c3D4e5F6g7H8i9J0k1L2"
	const github = "token=ghp_Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4J3h2"

	t.Run("git", func(t *testing.T) {
		repo := boundaryRepo(t, "leak.txt", aws)
		assertBoundaryKeyword(t, "git", "AWS", collectSourceChunks(t, &gitsource.Source{}, gitsource.Config{Repo: repo}))
	})
	t.Run("filesystem", func(t *testing.T) {
		dir := t.TempDir()
		_ = os.WriteFile(filepath.Join(dir, "leak.env"), []byte(aws), 0o600)
		assertBoundaryKeyword(t, "filesystem", "AWS", collectSourceChunks(t, &filesystem.Source{}, map[string]any{"paths": []string{dir}}))
	})
	t.Run("stdin", func(t *testing.T) {
		src := &stdinsource.Source{}
		src.SetReader(strings.NewReader(slack))
		assertBoundaryKeyword(t, "stdin", "SlackBotToken", collectSourceChunks(t, src, map[string]any{"label": "b3"}))
	})
	t.Run("archive", func(t *testing.T) {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		w, _ := zw.Create("leak.txt")
		_, _ = w.Write([]byte(github))
		_ = zw.Close()
		entries, err := archivepkg.Walk("fixture.zip", b.Bytes(), archivepkg.Limits{})
		if err != nil {
			t.Fatal(err)
		}
		var chunks [][]byte
		for _, e := range entries {
			chunks = append(chunks, e.Data)
		}
		assertBoundaryKeyword(t, "archive", "GitHub", chunks)
	})

	t.Run("github-collaboration", func(t *testing.T) {
		repo := githubRepoRef{Name: "repo"}
		repo.Owner.Login = "acme"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, []githubIssueComment{{ID: 1, Body: slack, UpdatedAt: "2026-07-10T00:00:00Z"}})
		}))
		defer srv.Close()
		var chunks [][]byte
		err := scanGitHubIssueCommentsIncremental(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("x")), repo, githubRepoIncrementalState{}, false, &githubRepoIncrementalState{}, "", func(data []byte, _ sources.Metadata) error {
			chunks = append(chunks, append([]byte(nil), data...))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertBoundaryKeyword(t, "github-collaboration", "SlackBotToken", chunks)
	})

	t.Run("github-wiki", func(t *testing.T) {
		repoPath := boundaryRepo(t, "Home.md", github)
		repo := githubRepoRef{Name: "repo", Visibility: "private"}
		repo.Owner.Login = "acme"
		var chunks [][]byte
		_, err := scanGitHubGitHistory(context.Background(), Config{}, staticGitHubToken(""), "github.com", repoPath, repo, githubRepoIncrementalState{}, true, func(data []byte, _ sources.Metadata) error {
			chunks = append(chunks, append([]byte(nil), data...))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertBoundaryKeyword(t, "github-wiki", "GitHub", chunks)
	})

	t.Run("github-gist", func(t *testing.T) {
		fixture := boundaryRepo(t, "gist.txt", aws)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/gists/") {
				writeJSON(t, w, githubGistRef{ID: "abc123", Public: true, GitPullURL: ""})
				return
			}
			t.Fatalf("unexpected %s", r.URL.Path)
		}))
		defer srv.Close()
		var chunks [][]byte
		err := scanGitHubGists(context.Background(), Config{"token": "x", "api_base": srv.URL, "gist_urls": "abc123", "gist_clone_url_template": fixture, "repo_concurrency": "1"}, staticGitHubToken("x"), srv.URL, func(data []byte, _ sources.Metadata) error {
			chunks = append(chunks, append([]byte(nil), data...))
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		assertBoundaryKeyword(t, "github-gist", "AWS", chunks)
	})
}
