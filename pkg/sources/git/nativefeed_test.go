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

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// feedChunks parses diff through parse (whole stream) or nativeLineFeed
// (writes of step bytes) and returns the emitted chunks.
func feedChunks(t *testing.T, diff string, step int) []*sources.Chunk {
	t.Helper()
	ch := make(chan *sources.Chunk, 64)
	p := &nativeLogParser{
		ctx:    context.Background(),
		source: &Source{},
		ch:     ch,
		commit: &nativeCommit{hash: strings.Repeat("1", 40)},
	}
	var err error
	if step == 0 {
		err = p.parse(strings.NewReader(diff))
	} else {
		feed := &nativeLineFeed{p: p}
		for b := []byte(diff); len(b) > 0 && err == nil; {
			n := min(step, len(b))
			_, err = feed.Write(b[:n])
			b = b[n:]
		}
		if err == nil {
			err = feed.Flush()
		}
		if err == nil {
			err = p.finish()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	close(ch)
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	return got
}

// TestNativeLineFeedMatchesParse pins the in-place feed (#1041) to parse:
// every write split, including lines spanning writes and an unterminated
// final line, yields the same chunks.
func TestNativeLineFeedMatchesParse(t *testing.T) {
	diff := "diff --git a/f.txt b/f.txt\n" +
		"--- a/f.txt\n+++ b/f.txt\n" +
		"@@ -1,2 +1,4 @@\n ctx1\n ctx2\n+SECRET=" + strings.Repeat("x", 300) + "\n" +
		"-gone\n+tail\n\\ No newline at end of file\n" +
		"diff --git a/g.txt b/g.txt\n--- a/g.txt\n+++ b/g.txt\n@@ -0,0 +1 @@\n+last"
	want := feedChunks(t, diff, 0)
	if len(want) != 2 {
		t.Fatalf("parse chunks=%d, want 2", len(want))
	}
	for _, step := range []int{1, 2, 7, 64, len(diff)} {
		got := feedChunks(t, diff, step)
		if len(got) != len(want) {
			t.Fatalf("step %d: chunks=%d, want %d", step, len(got), len(want))
		}
		for i := range want {
			if string(got[i].Data) != string(want[i].Data) || !reflect.DeepEqual(got[i].SourceMetadata, want[i].SourceMetadata) {
				t.Fatalf("step %d chunk %d: got %q %+v, want %q %+v", step, i, got[i].Data, got[i].SourceMetadata.Git, want[i].Data, want[i].SourceMetadata.Git)
			}
		}
	}
}

func TestNativeLineFeedRejectsOverlongHeaderLine(t *testing.T) {
	p := &nativeLogParser{ctx: context.Background(), source: &Source{}}
	feed := &nativeLineFeed{p: p}
	long := make([]byte, maxBlobSize+2)
	copy(long, "index ")
	if _, err := feed.Write(long); err == nil {
		t.Fatal("overlong non-hunk line accepted")
	}
}

func attrProbeRepo(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init")
	return dir
}

// TestProbeNoAttributeSources covers the #1042 proof: check-attr is skipped
// only when no attribute source can exist.
func TestProbeNoAttributeSources(t *testing.T) {
	ctx := context.Background()
	gitOut := func(dir string, args ...string) string {
		out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).Output()
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	dir := attrProbeRepo(t)
	if sys := gitOut(dir, "var", "GIT_ATTR_SYSTEM"); fileMayExist(sys) {
		t.Skipf("host has a system attributes file %s", sys)
	}
	if !probeNoAttributeSources(ctx, "git", dir) {
		t.Fatal("attribute-free repository not recognised")
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(dir string){
		"untracked nested": func(dir string) { write(filepath.Join(dir, "x", "y", ".gitattributes"), "*.txt -diff\n") },
		"ignored": func(dir string) {
			write(filepath.Join(dir, ".gitignore"), "ign/\n")
			write(filepath.Join(dir, "ign", ".gitattributes"), "*.txt -diff\n")
		},
		"info attributes": func(dir string) { write(filepath.Join(dir, ".git", "info", "attributes"), "*.txt -diff\n") },
		"global": func(dir string) {
			write(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "git", "attributes"), "*.txt -diff\n")
		},
		"core.attributesFile": func(dir string) {
			gitOut(dir, "config", "core.attributesFile", filepath.Join(dir, "missing-attrs"))
		},
		"attr.tree": func(dir string) { gitOut(dir, "config", "attr.tree", "HEAD") },
		"index only": func(dir string) {
			write(filepath.Join(dir, "sub", ".gitattributes"), "*.txt -diff\n")
			gitOut(dir, "add", "sub/.gitattributes")
			if err := os.Remove(filepath.Join(dir, "sub", ".gitattributes")); err != nil {
				t.Fatal(err)
			}
		},
		"bare": func(dir string) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			dir := attrProbeRepo(t)
			if name == "bare" {
				bare := filepath.Join(t.TempDir(), "b.git")
				if out, err := exec.Command("git", "clone", "-q", "--bare", dir, bare).CombinedOutput(); err != nil {
					t.Fatalf("%v: %s", err, out)
				}
				dir = bare
			}
			mutate(dir)
			if probeNoAttributeSources(ctx, "git", dir) {
				t.Fatalf("%s: attribute source missed", name)
			}
		})
	}
	t.Run("GIT_ATTR_SOURCE", func(t *testing.T) {
		dir := attrProbeRepo(t)
		t.Setenv("GIT_ATTR_SOURCE", "HEAD")
		if probeNoAttributeSources(ctx, "git", dir) {
			t.Fatal("GIT_ATTR_SOURCE ignored")
		}
	})
}

// TestNativeSynthMidCommitFallbackParity forces blob-limit fallbacks after
// earlier file pairs of the same commit were already sent (#1041): the
// combined stream must stay byte-identical to `git log -p`.
func TestNativeSynthMidCommitFallbackParity(t *testing.T) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	write("a.txt", "small\n")
	write("b.txt", strings.Repeat("big line\n", 40))
	write("c d.txt", "tiny\n")
	write("z.txt", "after\n")
	run("add", ".")
	run("commit", "-qm", "one")
	write("a.txt", "small 2\n")
	write("b.txt", strings.Repeat("big line\n", 39)+"changed\n")
	write("z.txt", "after 2\n")
	run("add", ".")
	run("commit", "-qm", "two")
	if err := os.Remove(filepath.Join(dir, "z.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.txt", filepath.Join(dir, "z.txt")); err != nil {
		t.Fatal(err)
	}
	write("y.txt", strings.Repeat("q", 200)+"\n")
	run("add", "-A")
	run("commit", "-qm", "three")

	old := nativeSynthMaxBlob
	t.Cleanup(func() { nativeSynthMaxBlob = old })
	for _, limit := range []int64{old, 100, 7} {
		nativeSynthMaxBlob = limit
		for _, reader := range []string{"", "git"} {
			t.Setenv("PLENO_DLP_GIT_OBJECT_READER", reader)
			s := &Source{repoAbs: dir, binaryBlobs: &binaryBlobCache{}, diffAttrs: &diffAttrCache{}}
			args := s.nativeLogArgs()
			want := renderGitPatch(t, args, "HEAD\n")
			got := renderNativeSynth(t, s, args, "HEAD\n")
			s.odb.close()
			if !bytes.Equal(want, got) {
				t.Fatalf("limit %d reader %q: rendered %d bytes, git %d\n%s", limit, reader, len(got), len(want), firstDiff(want, got))
			}
		}
	}
}

func TestNativeSectionSkipper(t *testing.T) {
	in := "\x1ehead\n:raw\n\ndiff --git a/x b/x\nindex 1..2\n@@ -1 +1 @@\n+diff --git inside\ndiff --git a/y b/y\n+y\ndiff --git a/z b/z\n+z"
	for _, skip := range []int{0, 1, 2, 3} {
		var want string
		if parts := strings.SplitAfterN(in, "\ndiff --git ", skip+2); len(parts) == skip+2 {
			want = "diff --git " + parts[skip+1]
		}
		for _, step := range []int{1, 3, 11, len(in)} {
			var out bytes.Buffer
			w := bufio.NewWriter(&out)
			sk := &nativeSectionSkipper{out: w, skip: skip}
			for b := []byte(in); len(b) > 0; {
				n := min(step, len(b))
				if _, err := sk.Write(b[:n]); err != nil {
					t.Fatal(err)
				}
				b = b[n:]
			}
			_ = w.Flush()
			if out.String() != want {
				t.Fatalf("skip %d step %d: got %q, want %q", skip, step, out.String(), want)
			}
		}
	}
}

// TestNativeLineFeedWriteLinesMatchesParse pins writeLines (#1046): hunk
// lines handed over at the renderer's recorded ends yield parse's chunks.
func TestNativeLineFeedWriteLinesMatchesParse(t *testing.T) {
	var x xdiffer
	a := []byte("keep\nold\nctx\nlast")
	b := []byte("keep\nSECRET=" + strings.Repeat("y", 40) + "\nctx\nlast\n")
	head := []byte("diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n")
	patch, any := x.unified(append([]byte(nil), head...), a, b)
	if !any {
		t.Fatal("no hunks")
	}
	want := feedChunks(t, string(patch), 0)
	ch := make(chan *sources.Chunk, 64)
	p := &nativeLogParser{ctx: context.Background(), source: &Source{}, ch: ch,
		commit: &nativeCommit{hash: strings.Repeat("1", 40)}}
	feed := &nativeLineFeed{p: p}
	if err := feed.writeLines(patch, len(head), x.ends); err != nil {
		t.Fatal(err)
	}
	if err := feed.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := p.finish(); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var got []*sources.Chunk
	for c := range ch {
		got = append(got, c)
	}
	if len(got) != len(want) || len(want) == 0 {
		t.Fatalf("chunks=%d, want %d", len(got), len(want))
	}
	for i := range want {
		if string(got[i].Data) != string(want[i].Data) || !reflect.DeepEqual(got[i].SourceMetadata, want[i].SourceMetadata) {
			t.Fatalf("chunk %d: got %q, want %q", i, got[i].Data, want[i].Data)
		}
	}
}
