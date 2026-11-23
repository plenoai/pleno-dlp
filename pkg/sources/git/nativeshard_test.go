package git

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func gitRun(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir, "-c", "user.name=T", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2026-05-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-05-01T00:00:00Z")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// buildShardRepo creates a history whose commits exercise the patch shapes
// that broke raw/patch alignment: a symlink turned into a regular file (one
// raw line, two diff headers), a deletion, and a merge.
func buildShardRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main")
	write := func(name, body string) {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("gone.txt", "doomed content\n")
	write(".gitattributes", "*.dat binary\n")
	if err := os.Symlink("gone.txt", filepath.Join(dir, "a-link")); err != nil {
		t.Skip("symlinks unsupported")
	}
	if err := os.Symlink("gone.txt", filepath.Join(dir, "a-bin")); err != nil {
		t.Skip("symlinks unsupported")
	}
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "c1")
	for i := 0; i < 5; i++ {
		write("filler.txt", strings.Repeat("x", i+1)+"\n")
		gitRun(t, dir, "add", "-A")
		gitRun(t, dir, "commit", "-qm", "filler")
	}
	if err := os.Remove(filepath.Join(dir, "a-link")); err != nil {
		t.Fatal(err)
	}
	write("a-link", "now a regular file secret-a\n")
	if err := os.Remove(filepath.Join(dir, "a-bin")); err != nil {
		t.Fatal(err)
	}
	write("a-bin", "\x89PNG\x00\x00binary\x00")
	write("b-added.txt", "added after the type change secret-b\n")
	write("c-added.txt", "added later secret-c\n")
	// Text that git renders as "Binary files differ" (attribute), placed
	// after two type changes so a misaligned raw path would lose it.
	write("z.dat", "attribute-binary text secret-z\n")
	gitRun(t, dir, "rm", "-q", "gone.txt")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "typechange")
	gitRun(t, dir, "checkout", "-q", "-b", "side")
	write("side.txt", "side branch\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "side")
	gitRun(t, dir, "checkout", "-q", "main")
	write("main.txt", "main branch\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "main")
	gitRun(t, dir, "merge", "-q", "--no-ff", "-m", "merge", "side")
	return dir
}

func chunkKeys(t *testing.T, dir string, minCommits int) []string {
	t.Helper()
	old := nativeShardMinCommits
	nativeShardMinCommits = minCommits
	defer func() { nativeShardMinCommits = old }()
	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	s.concurrency = 4
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatalf("Chunks: %v", err)
	}
	keys := make([]string, 0, len(got))
	for _, c := range got {
		g := c.SourceMetadata.Git
		keys = append(keys, g.Commit+" "+g.File+" "+string(c.Data))
	}
	sort.Strings(keys)
	return keys
}

// TestParallelShardsMatchSingleStream pins that sharded history rendering
// emits exactly the chunks of the single native stream.
func TestParallelShardsMatchSingleStream(t *testing.T) {
	dir := buildShardRepo(t)
	single := chunkKeys(t, dir, 1<<30)
	sharded := chunkKeys(t, dir, 1)
	if strings.Join(single, "\n") != strings.Join(sharded, "\n") {
		t.Fatalf("sharded chunks differ\nsingle:\n%s\nsharded:\n%s", strings.Join(single, "\n"), strings.Join(sharded, "\n"))
	}
	for i := 1; i < len(sharded); i++ {
		if sharded[i] == sharded[i-1] {
			t.Errorf("duplicate chunk %q (type-change raw/patch misalignment)", sharded[i])
		}
	}
	joined := strings.Join(sharded, "\n")
	for _, want := range []string{"secret-a", "secret-b", "secret-c", "secret-z"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in sharded chunks:\n%s", want, joined)
		}
	}
}

// TestChunksInlineMatchesChannel pins that the inline batch pool used by the
// engine delivers exactly the chunks of the plain channel path.
func TestChunksInlineMatchesChannel(t *testing.T) {
	dir := buildShardRepo(t)
	want := chunkKeys(t, dir, 1)

	old := nativeShardMinCommits
	nativeShardMinCommits = 1
	defer func() { nativeShardMinCommits = old }()
	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	s.concurrency = 4
	var mu sync.Mutex
	var got []string
	record := func(c *sources.Chunk) {
		g := c.SourceMetadata.Git
		mu.Lock()
		got = append(got, g.Commit+" "+g.File+" "+string(c.Data))
		mu.Unlock()
	}
	ch := make(chan *sources.Chunk)
	done := make(chan struct{})
	go func() {
		for c := range ch {
			record(c)
		}
		close(done)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.ChunksInline(ctx, ch, 3, record)
	close(ch)
	<-done
	if err != nil {
		t.Fatalf("ChunksInline: %v", err)
	}
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("inline chunks differ\nwant:\n%s\ngot:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
	if s.inlineBatches != nil {
		t.Fatal("inlineBatches leaked past ChunksInline")
	}
}
