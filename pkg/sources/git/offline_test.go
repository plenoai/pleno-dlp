package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// gitExec runs git inside dir; tests here need the real binary because
// partial-clone filters are a native-git transport feature.
func gitExec(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

// buildFilteredClone builds a source repo containing one blob above the
// filter ceiling, then mirror-clones it with --filter=blob:limit. Returns the
// clone path.
func buildFilteredClone(t *testing.T, limitKiB int) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not on PATH")
	}
	src := filepath.Join(t.TempDir(), "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "init", "-q")
	big := strings.Repeat("PROMISOR-OMITTED-LINE\n", limitKiB*64)
	if err := os.WriteFile(filepath.Join(src, "big.txt"), []byte(big), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "add", "-A")
	gitExec(t, src, "commit", "-qm", "c1")
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("alpha\nbeta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitExec(t, src, "commit", "-qam", "c2")
	// blob:limit filters only work when the transport permits filtering.
	cfgPath := filepath.Join(src, ".git", "config")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(cfg, []byte("[uploadpack]\n\tallowFilter = true\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(t.TempDir(), "clone")
	gitExec(t, t.TempDir(), "clone", "-q", "--mirror", "--no-local",
		"--filter=blob:limit="+strconv.Itoa(limitKiB)+"k", "file://"+src, clone)
	return clone
}

func TestRepoPromisorFilteredDetectsFilter(t *testing.T) {
	clone := buildFilteredClone(t, 1)
	s := &Source{repoAbs: clone}
	if !s.repoPromisorFiltered() {
		t.Fatal("promisor-filtered clone was not detected")
	}
	repo, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "x"}, msg: "c1"}})
	plain := &Source{repoAbs: repo}
	if plain.repoPromisorFiltered() {
		t.Fatal("ordinary repo reported as promisor-filtered")
	}
}

// TestChunks_OfflineWalkerSkipsOmittedBlobs verifies the promisor walk emits
// every locally present change, omits the filtered blob without failing, and
// never fetches it (GIT_NO_LAZY_FETCH is baked into nativeGitEnv).
func TestChunks_OfflineWalkerSkipsOmittedBlobs(t *testing.T) {
	clone := buildFilteredClone(t, 1)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})

	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	var files []string
	var sawAlpha, sawBeta bool
	for _, c := range got {
		if c.SourceMetadata.Git == nil {
			continue
		}
		files = append(files, c.SourceMetadata.Git.File)
		data := string(c.Data)
		if strings.Contains(data, "alpha") {
			sawAlpha = true
		}
		if strings.Contains(data, "beta") {
			sawBeta = true
		}
		if strings.Contains(data, "PROMISOR-OMITTED-LINE") {
			t.Fatalf("promisor-omitted blob content was emitted for %s", c.SourceMetadata.Git.File)
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("missing local content: sawAlpha=%v sawBeta=%v files=%v", sawAlpha, sawBeta, files)
	}
	for _, f := range files {
		if f == "big.txt" {
			t.Fatalf("filtered blob produced a chunk: %v", files)
		}
	}
	if s.IncrementalState() == nil {
		t.Fatal("incremental state was not published after a clean offline walk")
	}
}

// TestChunks_OfflineWalkerPreservesMetadata checks commit/author/file/line
// metadata survives the offline path unchanged.
func TestChunks_OfflineWalkerPreservesMetadata(t *testing.T) {
	clone := buildFilteredClone(t, 1)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})

	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("no chunks emitted")
	}
	for _, c := range got {
		meta := c.SourceMetadata.Git
		if meta == nil {
			t.Fatal("chunk missing git metadata")
		}
		if meta.Commit == "" || meta.File == "" || meta.Repository != clone {
			t.Fatalf("incomplete metadata: %+v", meta)
		}
		if meta.Author != "test" || meta.Email != "test@example.com" {
			t.Fatalf("author metadata mismatch: %+v", meta)
		}
	}
}



// TestChunksOfflineDirect exercises the offline native walker on the
// filtered clone regardless of whether this host's git qualifies for the
// native fast path.
func TestChunksOfflineDirect(t *testing.T) {
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	clone := buildFilteredClone(t, 1)
	s := &Source{}
	mustInit(t, s, Config{Repo: clone, AllBranches: true})
	s.repoAbs = clone

	repo, err := gogit.PlainOpen(clone)
	if err != nil {
		t.Fatalf("open clone: %v", err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ch := make(chan *sources.Chunk, 64)
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.chunksOffline(ctx, repo, gitBin, []plumbing.Hash{head.Hash()}, nil, ch)
		close(ch)
	}()
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("chunksOffline: %v", err)
	}
	var sawAlpha, sawBeta bool
	for _, c := range got {
		if strings.Contains(string(c.Data), "alpha") {
			sawAlpha = true
		}
		if strings.Contains(string(c.Data), "beta") {
			sawBeta = true
		}
		if strings.Contains(string(c.Data), "PROMISOR-OMITTED-LINE") {
			t.Fatal("omitted blob content emitted")
		}
	}
	if !sawAlpha || !sawBeta {
		t.Fatalf("missing local content: %d chunks", len(got))
	}
}
