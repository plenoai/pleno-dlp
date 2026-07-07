package git

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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

// TestChunks_ModificationEmitsAddedHunkOnly is the #264 mid-term-fix
// regression test: a full-history walk must emit only the added hunk (plus
// bounded context) for a modification, not the whole new file, or a large
// frequently-touched file gets rescanned end to end on every commit that
// changes it.
func TestChunks_ModificationEmitsAddedHunkOnly(t *testing.T) {
	var lines []string
	for i := 1; i <= 40; i++ {
		lines = append(lines, fmt.Sprintf("line-%02d unrelated code", i))
	}
	v1 := strings.Join(lines, "\n") + "\n"
	secretLine := "AWS_SECRET = \"AKIAABCDEFGHIJKLMNOP\""
	v2 := v1 + secretLine + "\n"

	repo, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"app.py": v1}, msg: "add file"},
		{files: map[string]string{"app.py": v2}, msg: "append secret"},
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

	add := got[1] // second commit: appends the secret line
	if add.SourceMetadata.Git.Commit == got[0].SourceMetadata.Git.Commit {
		t.Fatalf("expected two distinct commits")
	}

	// The secret must be present — this is the whole point of full-history
	// mode (detect newly introduced secrets).
	if !strings.Contains(string(add.Data), secretLine) {
		t.Fatalf("added-hunk chunk missing the newly introduced secret line; data=%q", add.Data)
	}
	// The chunk must be far smaller than the full new file: only the added
	// line plus a few lines of context, not all 41 lines.
	if len(add.Data) >= len(v2) {
		t.Fatalf("added-hunk chunk (%d bytes) not smaller than full file (%d bytes)", len(add.Data), len(v2))
	}
	// A line far from the change (well outside the context window) must be
	// absent — proof this is a hunk, not the full file.
	if strings.Contains(string(add.Data), "line-01 unrelated code") {
		t.Fatalf("added-hunk chunk leaked far-away context; data=%q", add.Data)
	}
	// Line metadata must point at the secret line's actual position in the
	// new file (41st line), not at the start of the emitted window.
	if add.SourceMetadata.Git.Line != 41 {
		t.Fatalf("Line: got %d, want 41", add.SourceMetadata.Git.Line)
	}
}

func TestFirstChangedLine_OversizedBlobSkipsDiff(t *testing.T) {
	// A single line changed near the start of an otherwise identical file
	// well over maxDiffBlobSize. If firstChangedLine actually diffed this
	// (like the small-file case in TestChunks_FirstChangedLine) it would
	// report line 1. The size guard must intercept it before change.Patch()
	// runs and report 0 instead.
	const chunk = "xxxx\n" // 5 bytes/line
	var b strings.Builder
	for i := 0; i < 250000; i++ { // 1,250,000 bytes > maxDiffBlobSize (1 MiB)
		b.WriteString(chunk)
	}
	v1 := b.String()
	v2 := "CHANGED\n" + v1[len(chunk):]

	repo, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"big.txt": v1}, msg: "c1"},
		{files: map[string]string{"big.txt": v2}, msg: "c2"},
	})

	r, err := gogit.PlainOpen(repo)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	c2, err := r.CommitObject(plumbing.NewHash(hashes[1]))
	if err != nil {
		t.Fatalf("CommitObject: %v", err)
	}
	newTree, err := c2.Tree()
	if err != nil {
		t.Fatalf("Tree: %v", err)
	}
	parent, err := c2.Parent(0)
	if err != nil {
		t.Fatalf("Parent: %v", err)
	}
	oldTree, err := parent.Tree()
	if err != nil {
		t.Fatalf("parent Tree: %v", err)
	}
	changes, err := object.DiffTreeWithOptions(context.Background(), oldTree, newTree, &object.DiffTreeOptions{DetectRenames: false})
	if err != nil {
		t.Fatalf("DiffTreeWithOptions: %v", err)
	}
	var change *object.Change
	for _, c := range changes {
		if c.To.Name == "big.txt" {
			change = c
			break
		}
	}
	if change == nil {
		t.Fatal("no change found for big.txt")
	}
	from, to, err := change.Files()
	if err != nil {
		t.Fatalf("Files: %v", err)
	}
	if to == nil || to.Size <= maxDiffBlobSize {
		t.Fatalf("fixture blob not oversized: to=%v", to)
	}

	if got := firstChangedLine(change, from, to); got != 0 {
		t.Fatalf("firstChangedLine on oversized blob = %d, want 0 (diff skipped)", got)
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

// TestBoundarySet_OnlyHeadsNotHistory guards #270: boundarySet used to be
// reachableSet, a BFS that walked and materialized every ancestor of each
// stop head into the returned map before the incremental walk even began —
// O(total previously-scanned history) instead of O(number of heads). Build
// a chain deep enough that a full-ancestry walk would visibly differ, and
// assert the result holds only the root itself.
func TestBoundarySet_OnlyHeadsNotHistory(t *testing.T) {
	specs := make([]commitSpec, 200)
	for i := range specs {
		specs[i] = commitSpec{files: map[string]string{"f.txt": strings.Repeat("x", i+1)}, msg: "c"}
	}
	repoPath, hashes := buildRepo(t, specs)
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	tip := plumbing.NewHash(hashes[len(hashes)-1])
	if _, err := repo.CommitObject(tip); err != nil {
		t.Fatalf("CommitObject(tip): %v", err)
	}

	set := boundarySet([]plumbing.Hash{tip})
	if len(set) != 1 {
		t.Fatalf("boundarySet size = %d, want 1 (root only, not the %d-commit ancestry behind it)", len(set), len(hashes))
	}
	if !set[tip] {
		t.Fatal("boundarySet missing the root hash")
	}
}

// TestChunks_IncrementalMultipleNewCommitsAheadOfRecordedHead strengthens
// TestChunks_IncrementalStateEmitsOnlyNewCommits: with boundarySet seeding
// seen from only the recorded head hash (not its ancestry, see #270), the
// forward walk from the new tip must still cross several new commits before
// it reaches and stops at that one recorded hash. A single-new-commit case
// cannot distinguish "correctly stopped at the boundary" from "got lucky."
func TestChunks_IncrementalMultipleNewCommitsAheadOfRecordedHead(t *testing.T) {
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

	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatalf("PlainOpen: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 10, 0, 0, time.UTC)
	var newHashes []string
	for i, spec := range []struct{ file, msg string }{
		{"c.txt", "c3"}, {"d.txt", "c4"}, {"e.txt", "c5"},
	} {
		h := commitOn(t, repo, map[string]string{spec.file: "new"}, spec.msg, base.Add(time.Duration(i)*time.Minute))
		newHashes = append(newHashes, h)
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
	if len(got) != len(newHashes) {
		t.Fatalf("second chunks = %d, want %d; files=%v", len(got), len(newHashes), filesOf(got))
	}
	for i, c := range got {
		if c.SourceMetadata.Git.Commit != newHashes[i] {
			t.Fatalf("chunk %d commit = %q, want %q (oldest-first across the 3 new commits)", i, c.SourceMetadata.Git.Commit, newHashes[i])
		}
	}
	if files := filesOf(got); files["a.txt"] || files["b.txt"] {
		t.Fatalf("incremental re-emitted a commit reachable from the recorded head; files=%v", files)
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

// commitOn commits the given files onto the repo's current worktree state and
// returns the new commit hash. The branch must already be checked out.
func commitOn(t *testing.T, repo *gogit.Repository, files map[string]string, msg string, when time.Time) string {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	root := wt.Filesystem.Root()
	for path, content := range files {
		full := filepath.Join(root, path)
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
	h, err := wt.Commit(msg, &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: when},
		Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: when},
	})
	if err != nil {
		t.Fatalf("commit %q: %v", msg, err)
	}
	return h.String()
}

func checkoutNewBranch(t *testing.T, repo *gogit.Repository, name string) {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{
		Branch: plumbing.NewBranchReferenceName(name),
		Create: true,
	}); err != nil {
		t.Fatalf("checkout -b %s: %v", name, err)
	}
}

func filesOf(chunks []*sources.Chunk) map[string]bool {
	out := map[string]bool{}
	for _, c := range chunks {
		if c.SourceMetadata.Git != nil {
			out[c.SourceMetadata.Git.File] = true
		}
	}
	return out
}

func TestChunks_AllBranchesEmitsSideBranchCommit(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commitOn(t, repo, map[string]string{"main.txt": "on-main"}, "c1", base)
	// Side branch carries a file reachable only from it.
	checkoutNewBranch(t, repo, "feature")
	commitOn(t, repo, map[string]string{"side.txt": "side-only"}, "c2-side", base.Add(time.Minute))

	// AllBranches=false (HEAD is now feature, but default contract walks HEAD
	// only). Switch back to a state where the side file is NOT on HEAD: check
	// out main so HEAD no longer reaches side.txt.
	wt, _ := repo.Worktree()
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		// go-git's default init branch may be "master" or "main"; try main.
		if err2 := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err2 != nil {
			t.Fatalf("checkout default branch: %v / %v", err, err2)
		}
	}

	// Default (single-branch) walk: side.txt must NOT appear.
	single := &Source{}
	mustInit(t, single, Config{Repo: dir})
	got, err := drain(t, single, 10*time.Second)
	if err != nil {
		t.Fatalf("single Chunks: %v", err)
	}
	if filesOf(got)["side.txt"] {
		t.Fatalf("single-branch walk leaked side-branch file; files=%v", filesOf(got))
	}
	if !filesOf(got)["main.txt"] {
		t.Fatalf("single-branch walk missing main.txt; files=%v", filesOf(got))
	}

	// AllBranches walk: side.txt MUST appear.
	all := &Source{}
	mustInit(t, all, Config{Repo: dir, AllBranches: true})
	got, err = drain(t, all, 10*time.Second)
	if err != nil {
		t.Fatalf("all-branches Chunks: %v", err)
	}
	files := filesOf(got)
	if !files["side.txt"] {
		t.Fatalf("all-branches walk missing side-branch file; files=%v", files)
	}
	if !files["main.txt"] {
		t.Fatalf("all-branches walk missing main.txt; files=%v", files)
	}
}

func TestChunks_AllBranchesEmitsSharedCommitOnce(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// Shared base commit reachable from both branches.
	commitOn(t, repo, map[string]string{"shared.txt": "shared"}, "base", base)
	checkoutNewBranch(t, repo, "feature")
	commitOn(t, repo, map[string]string{"feat.txt": "feat"}, "feat", base.Add(time.Minute))

	all := &Source{}
	mustInit(t, all, Config{Repo: dir, AllBranches: true})
	got, err := drain(t, all, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	var sharedCount int
	for _, c := range got {
		if c.SourceMetadata.Git != nil && c.SourceMetadata.Git.File == "shared.txt" {
			sharedCount++
		}
	}
	if sharedCount != 1 {
		t.Fatalf("shared commit emitted %d times, want exactly 1", sharedCount)
	}
}

func TestChunks_AllBranchesIncremental(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commitOn(t, repo, map[string]string{"a.txt": "a"}, "c1", base)
	checkoutNewBranch(t, repo, "feature")
	commitOn(t, repo, map[string]string{"b.txt": "b"}, "c2", base.Add(time.Minute))

	first := &Source{}
	mustInit(t, first, Config{Repo: dir, AllBranches: true})
	got, err := drain(t, first, 10*time.Second)
	if err != nil {
		t.Fatalf("first Chunks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("first run chunks=%d want 2; files=%v", len(got), filesOf(got))
	}
	state := first.IncrementalState()
	if len(state) == 0 {
		t.Fatal("first run produced no incremental state")
	}

	// Extend the side branch (reachable only from feature) and also add a
	// commit on feature whose parent is the recorded feature head.
	newHash := commitOn(t, repo, map[string]string{"c.txt": "c"}, "c3", base.Add(2*time.Minute))

	second := &Source{}
	mustInit(t, second, Config{Repo: dir, AllBranches: true})
	if err := second.SetIncrementalState(state); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	got, err = drain(t, second, 10*time.Second)
	if err != nil {
		t.Fatalf("second Chunks: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("second run chunks=%d want 1 (only new commit); files=%v", len(got), filesOf(got))
	}
	if got[0].SourceMetadata.Git.Commit != newHash {
		t.Fatalf("second run commit=%q want %q", got[0].SourceMetadata.Git.Commit, newHash)
	}
	if got[0].SourceMetadata.Git.File != "c.txt" {
		t.Fatalf("second run file=%q want c.txt", got[0].SourceMetadata.Git.File)
	}
}

func TestChunks_AllBranchesIncrementalSharedNotReemitted(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	// Base on default branch; record it as a prior head.
	commitOn(t, repo, map[string]string{"a.txt": "a"}, "c1", base)
	first := &Source{}
	mustInit(t, first, Config{Repo: dir, AllBranches: true})
	if _, err := drain(t, first, 10*time.Second); err != nil {
		t.Fatalf("first Chunks: %v", err)
	}
	state := first.IncrementalState()

	// New branch built ON TOP of the recorded head: its first commit's parent
	// is the old head (shared, must NOT re-emit), plus one genuinely new tip.
	checkoutNewBranch(t, repo, "feature")
	newHash := commitOn(t, repo, map[string]string{"b.txt": "b"}, "c2", base.Add(time.Minute))

	second := &Source{}
	mustInit(t, second, Config{Repo: dir, AllBranches: true})
	if err := second.SetIncrementalState(state); err != nil {
		t.Fatalf("SetIncrementalState: %v", err)
	}
	got, err := drain(t, second, 10*time.Second)
	if err != nil {
		t.Fatalf("second Chunks: %v", err)
	}
	if files := filesOf(got); files["a.txt"] {
		t.Fatalf("incremental re-emitted commit reachable from old head; files=%v", files)
	}
	if len(got) != 1 || got[0].SourceMetadata.Git.Commit != newHash {
		t.Fatalf("second run = %d chunks (want 1 new); files=%v", len(got), filesOf(got))
	}
}

// commitMerge commits the current index as a merge commit with two explicit
// parents. go-git's CommitOptions.Parents overrides the normal
// single-HEAD-parent default, letting a test build a real multi-parent
// commit without a full merge-conflict-resolution flow.
func commitMerge(t *testing.T, repo *gogit.Repository, files map[string]string, msg string, when time.Time, parents ...plumbing.Hash) string {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	root := wt.Filesystem.Root()
	for path, content := range files {
		full := filepath.Join(root, path)
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
	h, err := wt.Commit(msg, &gogit.CommitOptions{
		Parents:   parents,
		Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: when},
		Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: when},
	})
	if err != nil {
		t.Fatalf("commit merge %q: %v", msg, err)
	}
	return h.String()
}

// TestChunks_AllBranchesMergeCommitCollectsBothLineages guards the #263 fix's
// cross-head pruning: collectCommits shares a single "seen" set (passed as
// object.NewCommitPreorderIter's seenExternal) across every start's walk so a
// lineage already covered by an earlier start's walk is not re-walked. A
// merge commit gives that sharing a real chance to go wrong — one parent
// lineage may already be externally visited while a sibling parent (or a
// separate start processed afterward) is not, and go-git's iterator must
// only skip the individually-seen commit, never abort the walk and drop the
// rest. Here "feature" is processed as its own start AND is also reachable
// as the second parent of a merge commit reached via "master"; every commit
// in the DAG must still be collected exactly once, regardless of head order.
func TestChunks_AllBranchesMergeCommitCollectsBothLineages(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	base := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)

	c0 := commitOn(t, repo, map[string]string{"base.txt": "base"}, "c0", base)
	checkoutNewBranch(t, repo, "feature")
	cFeat := commitOn(t, repo, map[string]string{"feature.txt": "feature"}, "c-feat", base.Add(time.Minute))

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		if err2 := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err2 != nil {
			t.Fatalf("checkout default branch: %v / %v", err, err2)
		}
	}
	cMain := commitOn(t, repo, map[string]string{"main.txt": "main"}, "c-main", base.Add(2*time.Minute))
	cMerge := commitMerge(t, repo, map[string]string{"merge.txt": "merge"}, "c-merge", base.Add(3*time.Minute),
		plumbing.NewHash(cMain), plumbing.NewHash(cFeat))
	cAfter := commitOn(t, repo, map[string]string{"after.txt": "after"}, "c-after", base.Add(4*time.Minute))

	// Check out feature last so HEAD (added first by resolveStarts) is the
	// feature branch — forcing collectCommits to process "feature" before
	// "master"/"main", the ordering that walks into the merge commit's
	// second parent while it is already externally visited.
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("feature")}); err != nil {
		t.Fatalf("checkout feature: %v", err)
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: dir, AllBranches: true})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}

	wantCommits := []string{c0, cFeat, cMain, cMerge, cAfter}
	if len(got) != len(wantCommits) {
		t.Fatalf("chunks=%d want %d; files=%v", len(got), len(wantCommits), filesOf(got))
	}
	seen := map[string]int{}
	for _, c := range got {
		seen[c.SourceMetadata.Git.Commit]++
	}
	for _, want := range wantCommits {
		if seen[want] != 1 {
			t.Fatalf("commit %s emitted %d times, want exactly 1; all=%v", want, seen[want], seen)
		}
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
