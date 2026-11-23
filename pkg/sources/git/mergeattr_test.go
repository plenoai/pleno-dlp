package git

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildAttrBinaryMergeRepo resolves a conflict on a `*.dat binary` text file
// with content that appears in neither parent (#994).
func buildAttrBinaryMergeRepo(t *testing.T, secret string) string {
	return buildAttrBinaryMergeRepoWith(t, secret, false)
}

// buildAttrBinaryMergeRepoWith optionally marks *.dat binary only through
// .git/info/attributes instead of a committed .gitattributes.
func buildAttrBinaryMergeRepoWith(t *testing.T, secret string, infoOnly bool) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, dir, "init", "-q", "-b", "main")
	if infoOnly {
		if err := os.MkdirAll(filepath.Join(dir, ".git", "info"), 0o755); err != nil {
			t.Fatal(err)
		}
		write(".git/info/attributes", "*.dat binary\n")
	} else {
		write(".gitattributes", "*.dat binary\n")
	}
	write("conf.dat", "base\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "base")
	gitRun(t, dir, "checkout", "-q", "-b", "side")
	write("conf.dat", "side\n")
	gitRun(t, dir, "commit", "-qam", "side")
	gitRun(t, dir, "checkout", "-q", "main")
	write("conf.dat", "main\n")
	gitRun(t, dir, "commit", "-qam", "main")
	cmd := exec.Command("git", "-C", dir, "merge", "-q", "--no-ff", "side")
	_ = cmd.Run() // conflicts by design
	write("conf.dat", "resolved\ntoken = "+secret+"\n")
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-qm", "merge")
	return dir
}

func assertMergeAttrSecret(t *testing.T, dir, secret string) {
	t.Helper()
	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	got, err := drain(t, s, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range got {
		if strings.Contains(string(c.Data), secret) {
			if c.SourceMetadata.Git.File != "conf.dat" {
				t.Fatalf("secret attributed to %q", c.SourceMetadata.Git.File)
			}
			return
		}
	}
	t.Fatal("attribute-binary text introduced by a merge resolution was not scanned")
}

func TestChunks_NativeMergeResolutionAttributeBinaryText(t *testing.T) {
	const secret = "github_pat_11MERGEATTR_abcdefghijklmnopqrstuvwxyz0123456789"
	assertMergeAttrSecret(t, buildAttrBinaryMergeRepo(t, secret), secret)
}

func TestChunks_GoGitMergeResolutionAttributeBinaryText(t *testing.T) {
	const secret = "github_pat_11MERGEGOGIT_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := buildAttrBinaryMergeRepo(t, secret)
	t.Setenv("PATH", t.TempDir()) // no git binary: go-git walker
	assertMergeAttrSecret(t, dir, secret)
}

func TestChunks_NativeMergeResolutionInfoAttributesBinaryText(t *testing.T) {
	const secret = "github_pat_11MERGEINFO_abcdefghijklmnopqrstuvwxyz0123456789"
	assertMergeAttrSecret(t, buildAttrBinaryMergeRepoWith(t, secret, true), secret)
}
