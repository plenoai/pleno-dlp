package git

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// nativeRawRecord is one commit of a raw history stream, normalized to
// what the renderer consumes.
type nativeRawRecord struct {
	commit  nativeCommit
	entries []string
}

func parseRawRecords(t testing.TB, data []byte) []nativeRawRecord {
	t.Helper()
	var out []nativeRawRecord
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		switch {
		case len(line) == 0:
		case line[0] == nativeRecordSeparator:
			c, err := parseNativeCommit(line)
			if err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			out = append(out, nativeRawRecord{commit: c})
		case line[0] == ':':
			out[len(out)-1].entries = append(out[len(out)-1].entries, string(line))
		}
	}
	return out
}

// treeParity lists commits (newest first) through git and through the
// generator and requires identical records; it returns the fallback count.
func treeParity(t *testing.T, repo string, commits []string) int {
	t.Helper()
	ctx := context.Background()
	s := &Source{repoAbs: repo, binaryBlobs: &binaryBlobCache{}, diffAttrs: &diffAttrCache{}}
	if !s.nativeTreeDiffEligible(ctx, "git") {
		t.Fatal("repository not eligible for the in-process tree diff")
	}
	odb := s.objectDB(ctx, "git")
	if odb == nil {
		t.Fatal("no object store")
	}
	args := nativeRawArgs(s.nativeShardLogArgs())
	want := renderGitPatch(t, args, strings.Join(commits, "\n")+"\n")
	var buf bytes.Buffer
	w := bufio.NewWriter(&buf)
	helper, err := startNativeDiffTree(ctx, "git", repo)
	if err != nil {
		t.Fatal(err)
	}
	defer helper.close()
	g := &nativeRawGen{ctx: ctx, odb: odb.view(nativeTreeCache), git: helper, out: w}
	if err := g.run(commits); err != nil {
		t.Fatal(err)
	}
	wr, gr := parseRawRecords(t, want), parseRawRecords(t, buf.Bytes())
	if len(wr) != len(gr) {
		t.Fatalf("git listed %d commits, generator %d", len(wr), len(gr))
	}
	for i := range wr {
		if !reflect.DeepEqual(wr[i], gr[i]) {
			t.Fatalf("record %d differs:\ngit: %+v\ngen: %+v", i, wr[i], gr[i])
		}
	}
	return g.fallbacks
}

func revList(t *testing.T, repo string) []string {
	t.Helper()
	cmd := exec.Command("git", "-C", repo, "rev-list", "--all")
	cmd.Env = nativeGitEnv()
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Fields(string(out))
}

func TestNativeTreeDiffParity(t *testing.T) {
	repo := t.TempDir()
	git := func(env []string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(nativeGitEnv(), env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(repo, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ident := func(name, email, date string) []string {
		return []string{
			"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email, "GIT_AUTHOR_DATE=" + date,
			"GIT_COMMITTER_NAME=c", "GIT_COMMITTER_EMAIL=c@example.com", "GIT_COMMITTER_DATE=" + date,
		}
	}
	git(nil, "init", "-q")
	git(nil, "config", "commit.gpgsign", "false")
	write("a", "a\n")
	write("a-b", "x\n")
	write("dir/one", "1\n")
	write("dir/sub/two", "2\n")
	write("sp ace/f g", "s\n")
	write("ünï/çödé", "u\n")
	write("q\"uote\\back\ttab", "q\n")
	git(nil, "add", "-A")
	git(ident("Root  ", "root@example.com", "1700000000 +0000"), "commit", "-qm", "\n\n  root subject  \nsecond line\t\n\nbody")
	write("a", "a2\n")
	write("dir/sub/three", "3\n")
	git(nil, "add", "-A")
	git(ident("Ünïcode Name", "u@example.com", "1700000100 -0730"), "commit", "-qm", "modify and nest")
	git(nil, "rm", "-q", "a-b")
	git(ident("D", "d@example.com", "1700000200 +0545"), "commit", "-qm", "deletion only")
	git(ident("E", "e@example.com", "1700000300 +0100"), "commit", "-q", "--allow-empty", "-m", "empty")
	if err := os.Remove(filepath.Join(repo, "dir", "one")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(repo, "dir", "one")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(repo, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	git(nil, "add", "-A")
	git(ident("T", "t@example.com", "1700000400 +0000"), "commit", "-qm", "type and mode change")
	// A file replaced by a directory of the same name, and back.
	git(nil, "rm", "-q", "a")
	write("a/inner", "i\n")
	write("a.b", "dot\n")
	git(nil, "add", "-A")
	git(ident("F", "f@example.com", "1700000500 +0000"), "commit", "-qm", "file to dir")
	git(nil, "rm", "-qr", "a")
	write("a", "back\n")
	git(nil, "add", "-A")
	git(ident("G", "g@example.com", "1700000600 +0000"), "commit", "-qm", "dir to file")
	// A non-UTF-8 commit encoding is left to git.
	git(nil, "config", "i18n.commitEncoding", "ISO-8859-1")
	write("latin", "l\n")
	git(nil, "add", "-A")
	git(ident("L", "l@example.com", "1700000700 +0000"), "commit", "-qm", "latin1")
	git(nil, "config", "--unset", "i18n.commitEncoding")
	git(nil, "gc", "-q")

	commits := revList(t, repo)
	if fallbacks := treeParity(t, repo, commits); fallbacks != 1 {
		t.Fatalf("fallbacks = %d, want 1 (the ISO-8859-1 commit)", fallbacks)
	}
	// Loose objects are outside the object store and go to git.
	write("loose", "loose\n")
	git(nil, "add", "-A")
	git(ident("H", "h@example.com", "1700000800 +0000"), "commit", "-qm", "loose")
	commits = revList(t, repo)
	if fallbacks := treeParity(t, repo, commits); fallbacks != 2 {
		t.Fatalf("fallbacks = %d, want 2", fallbacks)
	}
}

func TestNativeTreeDiffEligibility(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
		cmd.Env = nativeGitEnv()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init", "-q")
	run("-c", "user.name=a", "-c", "user.email=a@example.com", "commit", "-q", "--allow-empty", "-m", "x")
	ctx := context.Background()
	eligible := func() bool { return (&Source{repoAbs: repo}).nativeTreeDiffEligible(ctx, "git") }
	if !eligible() {
		t.Fatal("plain repository not eligible")
	}
	if (&Source{repoAbs: repo, trufflehogCompatible: true}).nativeTreeDiffEligible(ctx, "git") {
		t.Fatal("trufflehog mode must keep git's rename detection")
	}
	run("config", "core.quotepath", "false")
	if eligible() {
		t.Fatal("core.quotepath=false must keep git")
	}
	run("config", "core.quotepath", "true")
	if !eligible() {
		t.Fatal("core.quotepath=true is the default")
	}
	run("config", "i18n.logOutputEncoding", "ISO-8859-1")
	if eligible() {
		t.Fatal("a non-UTF-8 output encoding must keep git")
	}
	run("config", "--unset", "i18n.logOutputEncoding")
	run("update-ref", "refs/replace/"+strings.Repeat("a", 40), "HEAD")
	if eligible() {
		t.Fatal("replace refs must keep git")
	}
	run("update-ref", "-d", "refs/replace/"+strings.Repeat("a", 40))
	if err := os.WriteFile(filepath.Join(repo, ".git", "shallow"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if eligible() {
		t.Fatal("a shallow repository must keep git")
	}
}

// TestNativeTreeDiffParityCorpus compares the generator with git over every
// commit (merges included) of PLENO_DLP_TREE_PARITY_REPO (benchmark corpora).
func TestNativeTreeDiffParityCorpus(t *testing.T) {
	repo := os.Getenv("PLENO_DLP_TREE_PARITY_REPO")
	if repo == "" {
		t.Skip("PLENO_DLP_TREE_PARITY_REPO not set")
	}
	commits := revList(t, repo)
	fallbacks := treeParity(t, repo, commits)
	t.Logf("%d commits identical, %d git fallbacks", len(commits), fallbacks)
}
