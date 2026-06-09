package git

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// fixture builds a fresh repo with a deterministic commit graph and returns
// its absolute path along with the SHAs of the commits in chronological order.
// We do not rely on the surrounding environment's git config — every test
// must work on a CI runner with no global identity.
type commitSpec struct {
	files map[string]string // path -> content (relative to repo root)
	msg   string
	when  time.Time
}

func buildRepo(t *testing.T, specs []commitSpec) (repoPath string, hashes []string) {
	t.Helper()
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	for i, s := range specs {
		for path, content := range s.files {
			full := filepath.Join(dir, path)
			if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			if err := os.WriteFile(full, []byte(content), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			if _, err := wt.Add(path); err != nil {
				t.Fatalf("add %q: %v", path, err)
			}
		}
		when := s.when
		if when.IsZero() {
			when = time.Date(2026, 5, 1, 0, i, 0, 0, time.UTC)
		}
		h, err := wt.Commit(s.msg, &gogit.CommitOptions{
			Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: when},
			Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: when},
		})
		if err != nil {
			t.Fatalf("commit %d: %v", i, err)
		}
		hashes = append(hashes, h.String())
	}
	return dir, hashes
}

func drain(t *testing.T, s *Source, deadline time.Duration) ([]*sources.Chunk, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	ch := make(chan *sources.Chunk, 64)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Chunks(ctx, ch); close(ch) }()
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	return got, <-errCh
}

func mustInit(t *testing.T, s *Source, cfg Config) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 2); err != nil {
		t.Fatalf("Init: %v", err)
	}
}

func TestChunks_LinearHistory(t *testing.T) {
	repo, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
		{files: map[string]string{"b.txt": "beta"}, msg: "c2"},
		{files: map[string]string{"a.txt": "alpha2"}, msg: "c3"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repo})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	// c1 introduces a.txt, c2 introduces b.txt, c3 modifies a.txt = 3 chunks.
	if len(got) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(got))
	}

	// Oldest-first: chunk 0 must reference c1.
	first := got[0]
	if first.SourceMetadata.Git == nil {
		t.Fatal("Git metadata missing")
	}
	if first.SourceMetadata.Git.Commit != hashes[0] {
		t.Fatalf("first commit: got %q want %q", first.SourceMetadata.Git.Commit, hashes[0])
	}
	if first.SourceMetadata.Git.File != "a.txt" {
		t.Fatalf("first file: got %q", first.SourceMetadata.Git.File)
	}
	if string(first.Data) != "alpha" {
		t.Fatalf("first data: got %q", first.Data)
	}
	if first.SourceMetadata.Git.Email != "test@example.com" {
		t.Fatalf("email: got %q", first.SourceMetadata.Git.Email)
	}
	if first.SourceMetadata.Git.Repository == "" || !filepath.IsAbs(first.SourceMetadata.Git.Repository) {
		t.Fatalf("repo path not absolute: %q", first.SourceMetadata.Git.Repository)
	}
	if first.SourceType != sources.SourceGit {
		t.Fatalf("SourceType: got %v", first.SourceType)
	}

	// Last chunk is c3's modification of a.txt with new content "alpha2".
	last := got[2]
	if last.SourceMetadata.Git.Commit != hashes[2] {
		t.Fatalf("last commit: got %q want %q", last.SourceMetadata.Git.Commit, hashes[2])
	}
	if string(last.Data) != "alpha2" {
		t.Fatalf("last data: got %q", last.Data)
	}
}

func TestChunks_SkipsBinary(t *testing.T) {
	bin := string(append([]byte("hello\x00world"), make([]byte, 100)...))
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"ok.txt": "text", "blob.bin": bin}, msg: "init"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repo})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (binary skipped), got %d", len(got))
	}
	if got[0].SourceMetadata.Git.File != "ok.txt" {
		t.Fatalf("expected ok.txt, got %q", got[0].SourceMetadata.Git.File)
	}
}

func TestChunks_IncludeExclude(t *testing.T) {
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{
			"keep.go":    "package keep",
			"skip.md":    "# docs",
			"vendor.txt": "third party",
		}, msg: "init"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repo, Include: []string{"*.go", "*.md"}, Exclude: []string{"*.md"}})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (only keep.go), got %d", len(got))
	}
	if got[0].SourceMetadata.Git.File != "keep.go" {
		t.Fatalf("got %q", got[0].SourceMetadata.Git.File)
	}
}

func TestChunks_MaxDepth(t *testing.T) {
	specs := make([]commitSpec, 5)
	for i := range specs {
		specs[i] = commitSpec{files: map[string]string{"f.txt": "v" + string(rune('0'+i))}, msg: "c"}
	}
	repo, _ := buildRepo(t, specs)
	s := &Source{}
	mustInit(t, s, Config{Repo: repo, MaxDepth: 2})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	// Walking newest 2 of 5 commits gives 2 chunks (f.txt modified each time).
	if len(got) != 2 {
		t.Fatalf("want 2 chunks (max_depth=2), got %d", len(got))
	}
}

func TestChunks_SinceFilter(t *testing.T) {
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	recent := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"old.txt": "old"}, msg: "old", when: old},
		{files: map[string]string{"new.txt": "new"}, msg: "new", when: recent},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repo, Since: "2026-01-01T00:00:00Z"})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 (since filter), got %d", len(got))
	}
	if got[0].SourceMetadata.Git.File != "new.txt" {
		t.Fatalf("got %q", got[0].SourceMetadata.Git.File)
	}
}

func TestChunks_FirstChangedLine(t *testing.T) {
	const v1 = "line1\nline2\nline3\n"
	const v2 = "line1\nlineTWO\nline3\n"
	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"f.txt": v1}, msg: "c1"},
		{files: map[string]string{"f.txt": v2}, msg: "c2"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repo})

	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(got))
	}
	// Initial-add chunk: line=1 (entire file is "added").
	if got[0].SourceMetadata.Git.Line != 1 {
		t.Fatalf("c1 line: got %d", got[0].SourceMetadata.Git.Line)
	}
	// Modified line is the 2nd one — the patch's first Add appears at new-side line 2.
	if got[1].SourceMetadata.Git.Line != 2 {
		t.Fatalf("c2 line: got %d (want 2)", got[1].SourceMetadata.Git.Line)
	}
}

func TestChunks_IncrementalStateEmitsOnlyNewCommits(t *testing.T) {
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "alpha"}, msg: "c1"},
		{files: map[string]string{"b.txt": "beta"}, msg: "c2"},
	})
	first := &Source{}
	mustInit(t, first, Config{Repo: repoPath})
	got, err := drain(t, first, 10*time.Second)
	if err != nil {
		t.Fatalf("first Chunks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("first chunks = %d, want 2", len(got))
	}
	previous := first.IncrementalState()
	if len(previous) == 0 {
		t.Fatal("first scan did not produce incremental state")
	}

	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "c.txt"), []byte("gamma"), 0o600); err != nil {
		t.Fatalf("write c.txt: %v", err)
	}
	if _, err := wt.Add("c.txt"); err != nil {
		t.Fatalf("add c.txt: %v", err)
	}
	newHash, err := wt.Commit("c3", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 5, 1, 0, 3, 0, 0, time.UTC)},
		Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 5, 1, 0, 3, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatalf("commit c3: %v", err)
	}

	second := &Source{}
	mustInit(t, second, Config{Repo: repoPath})
	if err := second.SetIncrementalState(previous); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	got, err = drain(t, second, 10*time.Second)
	if err != nil {
		t.Fatalf("second Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("second chunks = %d, want 1", len(got))
	}
	if got[0].SourceMetadata.Git.Commit != newHash.String() {
		t.Fatalf("commit = %q, want %q", got[0].SourceMetadata.Git.Commit, newHash.String())
	}
	if got[0].SourceMetadata.Git.File != "c.txt" {
		t.Fatalf("file = %q, want c.txt", got[0].SourceMetadata.Git.File)
	}
	if string(got[0].Data) != "gamma" {
		t.Fatalf("data = %q, want gamma", got[0].Data)
	}
}

func TestInit_MissingRepo(t *testing.T) {
	s := &Source{}
	raw, _ := json.Marshal(Config{Repo: filepath.Join(t.TempDir(), "nope")})
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 1); err == nil {
		t.Fatal("Init should fail on missing repo")
	}
}

func TestInit_EmptyRepo(t *testing.T) {
	s := &Source{}
	raw, _ := json.Marshal(Config{})
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 1); err == nil {
		t.Fatal("Init should require repo")
	}
}

func TestInit_BadSince(t *testing.T) {
	dir := t.TempDir()
	if _, err := gogit.PlainInit(dir, false); err != nil {
		t.Fatalf("init: %v", err)
	}
	s := &Source{}
	raw, _ := json.Marshal(Config{Repo: dir, Since: "yesterday"})
	if err := s.Init(context.Background(), "test", 1, 2, false, raw, 1); err == nil {
		t.Fatal("Init should reject non-RFC3339 since")
	}
}

func TestChunks_ContextCancel(t *testing.T) {
	specs := make([]commitSpec, 16)
	for i := range specs {
		specs[i] = commitSpec{files: map[string]string{"f.txt": strings.Repeat("x", i+1)}, msg: "c"}
	}
	repo, _ := buildRepo(t, specs)
	s := &Source{}
	mustInit(t, s, Config{Repo: repo})

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *sources.Chunk) // unbuffered: sends will block until consumer or cancel
	errCh := make(chan error, 1)
	go func() { errCh <- s.Chunks(ctx, ch) }()

	cancel()

	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want context.Canceled, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Chunks did not return after cancel")
	}
}

func TestRegistry_GitRegistered(t *testing.T) {
	s := sources.New(sources.SourceGit)
	if s == nil {
		t.Fatal("git source not registered")
	}
	if s.Type() != sources.SourceGit {
		t.Fatalf("Type: %v", s.Type())
	}
}
