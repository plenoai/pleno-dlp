package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCloneBlobLimitBytes(t *testing.T) {
	if got := CloneBlobLimitBytes(Config{}); got != maxBlobSize {
		t.Fatalf("default limit = %d, want %d", got, maxBlobSize)
	}
	// Artifact emission can raise the ceiling above the text cap only when a
	// caller opted into binary or archive scans.
	if got := CloneBlobLimitBytes(Config{GitArtifactMaxBytes: 100 << 20}); got != maxBlobSize {
		t.Fatalf("raised artifact cap without binary scan = %d, want %d", got, maxBlobSize)
	}
	if got := CloneBlobLimitBytes(Config{GitArtifactMaxBytes: 100 << 20, IncludeGitBinaries: true}); got != 100<<20 {
		t.Fatalf("binary scan limit = %d, want %d", got, 100<<20)
	}
	if got := CloneBlobLimitBytes(Config{GitArtifactMaxBytes: 100 << 20, IncludeGitArchives: true}); got != 100<<20 {
		t.Fatalf("archive scan limit = %d, want %d", got, 100<<20)
	}
	if got := CloneBlobLimitBytes(Config{GitArtifactMaxBytes: 1 << 20, IncludeGitBinaries: true}); got != maxBlobSize {
		t.Fatalf("artifact cap below text cap = %d, want %d", got, maxBlobSize)
	}
}

func TestIsPartialCloneRepo(t *testing.T) {
	dir, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "one"}, msg: "c1"}})
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	if isPartialCloneRepo(repo) {
		t.Fatal("complete clone reported as partial")
	}
	cfgPath := filepath.Join(dir, ".git", "config")
	f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("[remote \"origin\"]\n\tpromisor = true\n\tpartialclonefilter = blob:limit=1k\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if !isPartialCloneRepo(repo) {
		t.Fatal("promisor clone not detected from remote config")
	}
}

// TestChunks_PartialCloneSkipsOmittedBlobs builds a real promisor clone via
// `git clone --filter` and walks it end to end. Blobs above the filter limit
// are absent locally and must be classified as intentional skips: present
// blobs keep full coverage, the walk never fails, and nothing is fetched.
func TestChunks_PartialCloneSkipsOmittedBlobs(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{
			"small.txt": "small content v1\n",
			"big.bin":   strings.Repeat("B", 4096) + "\n",
		}, msg: "c1"},
		{files: map[string]string{
			"small.txt": "small content v2\n",
			"big.bin":   "now small\n",
		}, msg: "c2"},
	})
	gitConfig(t, src, "uploadpack.allowFilter", "true")

	dst := filepath.Join(t.TempDir(), "clone")
	clone := exec.Command("git", "clone", "--mirror", "--filter=blob:limit=1k", "--", "file://"+filepath.ToSlash(src), dst)
	if out, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("filtered clone: %v\n%s", err, out)
	}

	// Prove the oversized blob really is absent locally: with lazy fetching
	// disabled the object cannot be conjured back.
	missing := exec.Command("git", "-C", dst, "cat-file", "-e", blobHash(t, src, "HEAD^", "big.bin"))
	missing.Env = append(os.Environ(), "GIT_NO_LAZY_FETCH=1")
	if err := missing.Run(); err == nil {
		t.Fatal("oversized blob is present despite the blob filter")
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: dst, AllBranches: true})
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks on partial clone: %v", err)
	}
	if !s.partialClone {
		t.Fatal("walk did not detect the promisor clone")
	}
	var data strings.Builder
	for _, c := range got {
		data.Write(c.Data)
		data.WriteByte('\n')
	}
	all := data.String()
	for _, want := range []string{"small content v1", "small content v2", "now small"} {
		if !strings.Contains(all, want) {
			t.Fatalf("walk missed present-blob content %q; got %d chunks", want, len(got))
		}
	}
	if strings.Contains(all, strings.Repeat("B", 4096)) {
		t.Fatal("walk emitted content of an omitted promisor blob")
	}
	if s.partialSkips == 0 {
		t.Fatal("omitted blob was not counted as an intentional skip")
	}
}

// TestChunks_PartialCloneDeletionOfOmittedBlobIsQuiet covers a change whose
// only scannable side vanished: deleting an omitted blob emits nothing and
// counts as an intentional skip rather than an error.
func TestChunks_PartialCloneDeletionOfOmittedBlobIsQuiet(t *testing.T) {
	requireNativeGit(t)
	src, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"big.bin": strings.Repeat("D", 4096) + "\n"}, msg: "add"},
	})
	repo, err := gogit.PlainOpen(src)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Remove("big.bin"); err != nil {
		t.Fatal(err)
	}
	sig := &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC)}
	if _, err := wt.Commit("delete", &gogit.CommitOptions{Author: sig, Committer: sig}); err != nil {
		t.Fatal(err)
	}
	gitConfig(t, src, "uploadpack.allowFilter", "true")
	dst := filepath.Join(t.TempDir(), "clone")
	clone := exec.Command("git", "clone", "--mirror", "--filter=blob:limit=1k", "--", "file://"+filepath.ToSlash(src), dst)
	if out, err := clone.CombinedOutput(); err != nil {
		t.Fatalf("filtered clone: %v\n%s", err, out)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dst, AllBranches: true})
	if _, err := drain(t, s, 30*time.Second); err != nil {
		t.Fatalf("Chunks on partial clone with omitted deletion: %v", err)
	}
	if s.partialSkips == 0 {
		t.Fatal("omitted deletion was not counted as an intentional skip")
	}
}

// TestChunks_MissingBlobCompleteCloneFails proves the tolerance is gated on
// the promisor-clone signal: the same absent blob in a complete repository is
// corruption, not an intentional skip, and must still surface as an error.
func TestChunks_MissingBlobCompleteCloneFails(t *testing.T) {
	dir, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "one"}, msg: "c1"}})
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatal(err)
	}
	tree, err := commit.Tree()
	if err != nil {
		t.Fatal(err)
	}
	var blob string
	for _, entry := range tree.Entries {
		if entry.Name == "a.txt" {
			blob = entry.Hash.String()
		}
	}
	if blob == "" {
		t.Fatal("fixture blob not found")
	}
	objPath := filepath.Join(dir, ".git", "objects", blob[:2], blob[2:])
	if err := os.Remove(objPath); err != nil {
		t.Fatalf("remove blob object: %v", err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	if _, err := drain(t, s, 30*time.Second); err == nil {
		t.Fatal("missing blob in a complete clone did not fail the walk")
	}
}

func gitConfig(t *testing.T, dir, key, value string) {
	t.Helper()
	cmd := exec.Command("git", "-C", dir, "config", key, value)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git config %s: %v\n%s", key, err, out)
	}
}

func blobHash(t *testing.T, repoDir, rev, path string) string {
	t.Helper()
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", rev+":"+path)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("rev-parse %s:%s: %v", rev, path, err)
	}
	return strings.TrimSpace(string(out))
}
