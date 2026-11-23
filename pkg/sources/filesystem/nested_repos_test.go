package filesystem

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

func TestScanNestedReposWalksHistory(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	repo := filepath.Join(root, "projects", "child")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo, "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	if err := os.WriteFile(filepath.Join(repo, "old.env"), []byte("HISTORY_ONLY_MARKER=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	git("commit", "-qm", "add")
	git("rm", "-q", "old.env")
	git("commit", "-qm", "remove")
	if err := os.WriteFile(filepath.Join(root, "top.txt"), []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scan := func(nested bool) (fsChunks, gitHits int) {
		cfg, _ := json.Marshal(Config{Paths: []string{root}, ScanNestedRepos: nested})
		s := &Source{}
		if err := s.Init(context.Background(), "t", 0, 0, false, cfg, 2); err != nil {
			t.Fatal(err)
		}
		chunks, err := drain(t, s, 30*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range chunks {
			if c.SourceMetadata.Git != nil && bytes.Contains(c.Data, []byte("HISTORY_ONLY_MARKER")) {
				gitHits++
			}
			if c.SourceMetadata.Filesystem != nil {
				fsChunks++
			}
		}
		return
	}
	if fsN, hits := scan(false); hits != 0 || fsN == 0 {
		t.Fatalf("without flag: fs=%d git hits=%d", fsN, hits)
	}
	if fsN, hits := scan(true); hits == 0 || fsN == 0 {
		t.Fatalf("with flag: fs=%d git hits=%d (history not scanned)", fsN, hits)
	}
}
