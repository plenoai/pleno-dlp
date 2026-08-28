package git

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestNativeLogArgsPreserveWalkConstraints(t *testing.T) {
	s := &Source{
		repoAbs:  "/repo",
		maxDepth: 7,
		since:    time.Unix(1_700_000_000, 0),
	}
	start := plumbing.NewHash("1111111111111111111111111111111111111111")
	stop := plumbing.NewHash("2222222222222222222222222222222222222222")
	args := s.nativeLogArgs()

	for _, want := range []string{
		"--patch", "--root", "--reverse", "--topo-order", "--full-history",
		"--no-show-signature", "--raw", "--abbrev=40", "--no-renames",
		"--no-ext-diff", "--no-textconv", "--no-indent-heuristic",
		"--inter-hunk-context=0", "--ignore-submodules=all",
		"--diff-algorithm=myers", "--diff-merges=off", "--unified=3",
		"--src-prefix=a/", "--dst-prefix=b/",
		"--max-count=7", "--since-as-filter=@1700000000",
		"--stdin", "--",
	} {
		if !slices.Contains(args, want) {
			t.Fatalf("native log args missing %q: %v", want, args)
		}
	}
	if got, want := nativeRevisionInput([]plumbing.Hash{start}, []plumbing.Hash{stop}), start.String()+"\n^"+stop.String()+"\n"; got != want {
		t.Fatalf("native revision input=%q, want %q", got, want)
	}
}

func TestNativeLogArgsTrufflehogCompatible(t *testing.T) {
	s := &Source{repoAbs: "/repo", trufflehogCompatible: true}
	args := s.nativeLogArgs()
	for _, want := range []string{"--find-renames", "--diff-filter=AM", "--diff-merges=off"} {
		if !slices.Contains(args, want) {
			t.Fatalf("trufflehog-compatible args missing %q: %v", want, args)
		}
	}
	if slices.Contains(args, "--no-renames") {
		t.Fatalf("trufflehog-compatible args retain --no-renames: %v", args)
	}
}

func TestGitRenameOptionsTrufflehogCompatible(t *testing.T) {
	if gitRenameOptions(false).DetectRenames {
		t.Fatal("default rename options enabled rename detection")
	}
	opts := gitRenameOptions(true)
	if !opts.DetectRenames || opts.RenameScore != 50 || opts.RenameLimit != 1000 {
		t.Fatalf("trufflehog-compatible diff-tree options = %+v", opts)
	}
}

func TestSameGitDiffType(t *testing.T) {
	if !sameGitDiffType(filemode.Regular, filemode.Executable) {
		t.Fatal("executable-bit change must remain a modification")
	}
	if sameGitDiffType(filemode.Regular, filemode.Symlink) {
		t.Fatal("regular-to-symlink change must be a type change")
	}
}

func TestParseNativeCommitTracksMergeParents(t *testing.T) {
	hash := "1111111111111111111111111111111111111111"
	parent1 := "2222222222222222222222222222222222222222"
	parent2 := "3333333333333333333333333333333333333333"
	record := string(nativeRecordSeparator) + hash + string(nativeFieldSeparator) +
		parent1 + " " + parent2 + string(nativeFieldSeparator) +
		"Test" + string(nativeFieldSeparator) +
		"test@example.com" + string(nativeFieldSeparator) +
		"2026-07-01T00:00:00Z" + string(nativeFieldSeparator) +
		"merge" + string(nativeFieldSeparator) + "\n"

	commit, err := parseNativeCommit([]byte(record))
	if err != nil {
		t.Fatal(err)
	}
	if commit.hash != hash || commit.parentCount != 2 {
		t.Fatalf("commit=%+v", commit)
	}
	var mergeInput strings.Builder
	parser := nativeLogParser{mergeInput: &mergeInput}
	if err := parser.consumeLine([]byte(record)); err != nil {
		t.Fatal(err)
	}
	if got, want := mergeInput.String(), hash+"\n"; got != want {
		t.Fatalf("merge input=%q, want %q", got, want)
	}
}

func TestChunks_NativePreservesMetadataAndNoFinalNewline(t *testing.T) {
	requireNativeGit(t)
	base := time.Date(2026, 7, 1, 2, 3, 4, 0, time.FixedZone("JST", 9*60*60))
	payload := string([]byte{nativeRecordSeparator}) + "not-a-record"
	repoPath, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"quoted name.txt": "context\n"}, msg: "base", when: base},
		{files: map[string]string{"quoted name.txt": "context\n" + payload}, msg: "same author", when: base.Add(time.Minute)},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var changed *sources.Chunk
	for _, chunk := range got {
		if chunk.SourceMetadata.Git.Commit == hashes[1] {
			changed = chunk
			break
		}
	}
	if changed == nil {
		t.Fatalf("second commit missing: %#v", got)
	}
	if string(changed.Data) != "context\n"+payload {
		t.Fatalf("data=%q, want exact no-final-newline payload", changed.Data)
	}
	if changed.Data[len(changed.Data)-1] == '\n' {
		t.Fatal("native patch invented a final newline")
	}
	meta := changed.SourceMetadata.Git
	if meta.Author != "Test" || meta.Email != "test@example.com" || meta.Message != "same author" {
		t.Fatalf("metadata=%+v", meta)
	}
	if meta.AuthoredDate != base.Add(time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("authored date=%q", meta.AuthoredDate)
	}
}

func TestChunks_TrufflehogCompatibleBlanksContext(t *testing.T) {
	requireNativeGit(t)
	repoPath, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"config.txt": "before\nold\nafter\n"}, msg: "base"},
		{files: map[string]string{"config.txt": "before\nadded\nafter\n"}, msg: "change"},
	})
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "native", cfg: Config{Repo: repoPath, TrufflehogCompatible: true}},
		{name: "go-git fallback", cfg: Config{Repo: repoPath, TrufflehogCompatible: true, IncludeCommitMetadata: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, tc.cfg)
			got, err := drain(t, s, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			var changed *sources.Chunk
			for _, chunk := range got {
				meta := chunk.SourceMetadata.Git
				if meta != nil && meta.Commit == hashes[1] && meta.File == "config.txt" {
					changed = chunk
					break
				}
			}
			if changed == nil {
				t.Fatalf("changed file chunk missing: %v", filesOf(got))
			}
			if got, want := string(changed.Data), "\nadded\n\n"; got != want {
				t.Fatalf("data=%q, want trufflehog-compatible context %q", got, want)
			}
		})
	}
}

func TestChunks_TrufflehogCompatibleSkipsRenameDiffs(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"old.txt": "unchanged content\n"}, msg: "base"},
	})
	for _, args := range [][]string{
		{"mv", "old.txt", "renamed.txt"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgSign=false", "commit", "-m", "rename"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	hashOutput, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	renameHash := strings.TrimSpace(string(hashOutput))

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "native", cfg: Config{Repo: repoPath, TrufflehogCompatible: true}},
		{name: "go-git fallback", cfg: Config{Repo: repoPath, TrufflehogCompatible: true, IncludeCommitMetadata: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, tc.cfg)
			got, err := drain(t, s, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range got {
				meta := chunk.SourceMetadata.Git
				if meta != nil && meta.Commit == renameHash && meta.File == "renamed.txt" {
					t.Fatalf("rename diff emitted in trufflehog-compatible mode: %#v", meta)
				}
			}
		})
	}
}

func TestChunks_TrufflehogCompatibleFallbackSkipsEditedExecutableRename(t *testing.T) {
	requireNativeGit(t)
	var shared strings.Builder
	for i := 0; i < 40; i++ {
		fmt.Fprintf(&shared, "shared-line-%02d\n", i)
	}
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"old.txt": shared.String() + strings.Repeat("old-only\n", 5)}, msg: "base"},
	})
	for _, args := range [][]string{
		{"update-index", "--chmod=+x", "old.txt"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgSign=false", "commit", "-m", "make executable"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	if out, err := exec.Command("git", "-C", repoPath, "mv", "old.txt", "renamed.txt").CombinedOutput(); err != nil {
		t.Fatalf("git mv: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "renamed.txt"), []byte(shared.String()+strings.Repeat("new-only\n", 5)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "renamed.txt"},
		{"update-index", "--chmod=+x", "renamed.txt"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgSign=false", "commit", "-m", "edited rename"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	hashOutput, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	renameHash := strings.TrimSpace(string(hashOutput))

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath, TrufflehogCompatible: true, IncludeCommitMetadata: true})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		meta := chunk.SourceMetadata.Git
		if meta != nil && meta.Commit == renameHash && meta.File == "renamed.txt" {
			t.Fatalf("edited executable rename emitted by trufflehog-compatible fallback: %#v", meta)
		}
	}
}

func TestChunks_TrufflehogCompatibleFallbackKeepsUnrelatedAddition(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"old.txt": strings.Repeat("old-only-alpha\n", 32)}, msg: "base"},
	})
	if err := os.Remove(filepath.Join(repoPath, "old.txt")); err != nil {
		t.Fatal(err)
	}
	const marker = "new-only-omega"
	if err := os.WriteFile(filepath.Join(repoPath, "new.txt"), []byte(strings.Repeat(marker+"\n", 32)), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "-A"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgSign=false", "commit", "-m", "replace unrelated file"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	hashOutput, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	replaceHash := strings.TrimSpace(string(hashOutput))

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath, TrufflehogCompatible: true, IncludeCommitMetadata: true})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		meta := chunk.SourceMetadata.Git
		if meta == nil || meta.Commit != replaceHash || meta.File != "new.txt" {
			continue
		}
		if !strings.Contains(string(chunk.Data), marker) {
			t.Fatalf("unrelated addition missing marker: %q", chunk.Data)
		}
		return
	}
	t.Fatal("unrelated addition was misclassified as a rename")
}

func TestChunks_TrufflehogCompatibleSkipsTypeChanges(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"kind.txt": "regular content\n"}, msg: "base"},
	})
	if err := os.Remove(filepath.Join(repoPath, "kind.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("symlink-target", filepath.Join(repoPath, "kind.txt")); err != nil {
		t.Skipf("symlink fixture unavailable: %v", err)
	}
	for _, args := range [][]string{
		{"add", "-A"},
		{"-c", "user.name=Test", "-c", "user.email=test@example.com", "-c", "commit.gpgSign=false", "commit", "-m", "change file type"},
	} {
		if out, err := exec.Command("git", append([]string{"-C", repoPath}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, out)
		}
	}
	hashOutput, err := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	typeChangeHash := strings.TrimSpace(string(hashOutput))

	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{name: "native", cfg: Config{Repo: repoPath, TrufflehogCompatible: true}},
		{name: "go-git fallback", cfg: Config{Repo: repoPath, TrufflehogCompatible: true, IncludeCommitMetadata: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, tc.cfg)
			got, err := drain(t, s, 10*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			for _, chunk := range got {
				meta := chunk.SourceMetadata.Git
				if meta != nil && meta.Commit == typeChangeHash && meta.File == "kind.txt" {
					t.Fatalf("type-change diff emitted in trufflehog-compatible mode: %#v", meta)
				}
			}
		})
	}
}

func TestChunks_NativeHandlesQuotedPath(t *testing.T) {
	requireNativeGit(t)
	path := "dir/quote\"snowman-☃.txt"
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{path: "secret"}, msg: "quoted path"}})
	if out, err := exec.Command("git", "-C", repoPath, "config", "diff.noprefix", "true").CombinedOutput(); err != nil {
		t.Fatalf("git config diff.noprefix: %v: %s", err, out)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceMetadata.Git.File != path || string(got[0].Data) != "secret" {
		t.Fatalf("quoted path chunks=%#v", got)
	}
}

func TestChunks_NativeIgnoresInheritedGitDir(t *testing.T) {
	requireNativeGit(t)
	selectedPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"selected.txt": "selected-only"}, msg: "selected"}})
	overridePath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"override.txt": "override-only"}, msg: "override"}})
	t.Setenv("GIT_DIR", filepath.Join(overridePath, ".git"))

	s := &Source{}
	mustInit(t, s, Config{Repo: selectedPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].SourceMetadata.Git.File != "selected.txt" || string(got[0].Data) != "selected-only" {
		t.Fatalf("inherited GIT_DIR changed selected repository: %#v", got)
	}
}

func TestChunks_NativeIgnoresReplaceRefs(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11REPLACEHIDDEN_abcdefghijklmnopqrstuvwxyz0123456789"
	repoPath, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"secret.txt": secret + "\n"}, msg: "secret"},
		{files: map[string]string{"secret.txt": "safe\n"}, msg: "remove secret"},
	})

	treeCmd := exec.Command("git", "-C", repoPath, "show", "-s", "--format=%T", hashes[1])
	treeOutput, err := treeCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git show tree: %v: %s", err, treeOutput)
	}
	commitCmd := exec.Command("git", "-C", repoPath, "commit-tree", strings.TrimSpace(string(treeOutput)), "-m", "replacement")
	commitCmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	replacementOutput, err := commitCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git commit-tree: %v: %s", err, replacementOutput)
	}
	replacement := strings.TrimSpace(string(replacementOutput))
	if out, err := exec.Command("git", "-C", repoPath, "replace", hashes[0], replacement).CombinedOutput(); err != nil {
		t.Fatalf("git replace: %v: %s", err, out)
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if strings.Contains(string(chunk.Data), secret) {
			return
		}
	}
	t.Fatal("refs/replace hid a secret from the native history walk")
}

func TestChunks_NativeTextOverridesBinaryAttribute(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11ATTRTEXT_abcdefghijklmnopqrstuvwxyz0123456789"
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{".gitattributes": "secret.dat -diff\n", "secret.dat": "safe\n"}, msg: "base"},
		{files: map[string]string{".gitattributes": "secret.dat -diff\n", "secret.dat": "safe\n" + secret + "\n"}, msg: "secret"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if strings.Contains(string(chunk.Data), secret) {
			return
		}
	}
	t.Fatal(".gitattributes -diff suppressed text secret")
}

func TestChunks_NativeOverridesSuppressBlankEmpty(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11BLANKCONTEXT_abcdefghijklmnopqrstuvwxyz0123456789"
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"secret.txt": "top\n\nbottom\n"}, msg: "base"},
		{files: map[string]string{"secret.txt": "top\n\n" + secret + "\nbottom\n"}, msg: "secret"},
	})
	if out, err := exec.Command("git", "-C", repoPath, "config", "diff.suppressBlankEmpty", "true").CombinedOutput(); err != nil {
		t.Fatalf("git config: %v: %s", err, out)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if strings.Contains(string(chunk.Data), secret) {
			return
		}
	}
	t.Fatal("diff.suppressBlankEmpty hid a later addition in the hunk")
}

func TestChunks_NativeTreatsPatchMarkersAsHunkContent(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"markers.txt": "-- old\n"}, msg: "base"},
		{files: map[string]string{"markers.txt": "++ new\n"}, msg: "update"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if chunk.SourceMetadata.Git.File == "markers.txt" && strings.Contains(string(chunk.Data), "++ new") {
			return
		}
	}
	t.Fatalf("hunk content beginning with patch markers was not emitted: %#v", got)
}

func TestNativeLogParserStreamsTextAfterBufferLimit(t *testing.T) {
	repoPath, hashes := buildRepo(t, []commitSpec{{
		files: map[string]string{"large.txt": "first\nmiddle\nsecond\n"},
		msg:   "large text",
	}})
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	ch := make(chan *sources.Chunk, 2)
	parser := nativeLogParser{
		ctx:         context.Background(),
		source:      s,
		repo:        repo,
		ch:          ch,
		commit:      &nativeCommit{hash: hashes[0]},
		bufferLimit: 8,
	}
	diff := "diff --git a/large.txt b/large.txt\n" +
		"--- a/large.txt\n+++ b/large.txt\n" +
		"@@ -0,0 +1 @@\n+first\n" +
		"@@ -0,0 +3 @@\n+second\n"
	if err := parser.parse(strings.NewReader(diff)); err != nil {
		t.Fatal(err)
	}
	close(ch)
	var data strings.Builder
	for chunk := range ch {
		data.Write(chunk.Data)
	}
	if got := data.String(); got != "first\nsecond\n" {
		t.Fatalf("streamed data=%q", got)
	}
}

func TestNativeLogParserDropsBinaryAfterBufferLimit(t *testing.T) {
	repoPath, hashes := buildRepo(t, []commitSpec{{
		files: map[string]string{"large.bin": "first\n\x00\nsecond\n"},
		msg:   "large binary",
	}})
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	ch := make(chan *sources.Chunk, 2)
	parser := nativeLogParser{
		ctx:         context.Background(),
		source:      s,
		repo:        repo,
		ch:          ch,
		commit:      &nativeCommit{hash: hashes[0]},
		bufferLimit: 8,
	}
	diff := "diff --git a/large.bin b/large.bin\n" +
		"--- a/large.bin\n+++ b/large.bin\n" +
		"@@ -0,0 +1 @@\n+first\n" +
		"@@ -0,0 +3 @@\n+second\n"
	if err := parser.parse(strings.NewReader(diff)); err != nil {
		t.Fatal(err)
	}
	if len(ch) != 0 {
		t.Fatalf("binary file emitted %d chunks", len(ch))
	}
}

func TestNativeLogParserKeepsExcludedFileDiscardedAfterBufferLimit(t *testing.T) {
	ch := make(chan *sources.Chunk, 1)
	parser := nativeLogParser{
		ctx:         context.Background(),
		source:      &Source{exclude: []string{"*.txt"}},
		ch:          ch,
		commit:      &nativeCommit{hash: strings.Repeat("1", 40)},
		file:        nativeFilePatch{path: "excluded.txt"},
		bufferLimit: 1,
	}
	if err := parser.appendFile([]byte("first"), 1); err != nil {
		t.Fatal(err)
	}
	if err := parser.appendFile([]byte("second"), 2); err != nil {
		t.Fatal(err)
	}
	if !parser.file.discard {
		t.Fatal("excluded file did not remain discarded")
	}
	if len(ch) != 0 {
		t.Fatalf("excluded file emitted %d chunks", len(ch))
	}
}

func TestNativeLogParserClassifiesLargeFilesWithNativeGit(t *testing.T) {
	requireNativeGit(t)
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		content string
		want    string
	}{
		{name: "text", content: "first\nsecond\n", want: "first\nsecond\n"},
		{name: "binary", content: "first\n\x00\nsecond\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			repoPath, hashes := buildRepo(t, []commitSpec{{
				files: map[string]string{"large.txt": tt.content},
				msg:   "large file",
			}})
			s := &Source{}
			mustInit(t, s, Config{Repo: repoPath})
			ch := make(chan *sources.Chunk, 2)
			parser := nativeLogParser{
				ctx:         context.Background(),
				source:      s,
				gitBin:      gitBin,
				ch:          ch,
				commit:      &nativeCommit{hash: hashes[0]},
				bufferLimit: 8,
			}
			diff := "diff --git a/large.txt b/large.txt\n" +
				"--- a/large.txt\n+++ b/large.txt\n" +
				"@@ -0,0 +1 @@\n+first\n" +
				"@@ -0,0 +2 @@\n+second\n"
			if err := parser.parse(strings.NewReader(diff)); err != nil {
				t.Fatal(err)
			}
			close(ch)
			var got strings.Builder
			for chunk := range ch {
				got.Write(chunk.Data)
			}
			if got.String() != tt.want {
				t.Fatalf("data=%q, want %q", got.String(), tt.want)
			}
		})
	}
}

func TestNativeLogParserStreamsAddedLineBeyondBlobLimit(t *testing.T) {
	repoPath, hashes := buildRepo(t, []commitSpec{{
		files: map[string]string{"large.txt": "text\n"},
		msg:   "large text",
	}})
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	ch := make(chan *sources.Chunk, 2)
	type result struct {
		chunks          int
		maxLen          int
		found           bool
		markerLine      int
		lastEndsNewline bool
	}
	resultCh := make(chan result, 1)
	const marker = "tail-marker-after-limit"
	go func() {
		var got result
		for chunk := range ch {
			got.chunks++
			if len(chunk.Data) > got.maxLen {
				got.maxLen = len(chunk.Data)
			}
			if bytes.Contains(chunk.Data, []byte(marker)) {
				got.found = true
				got.markerLine = chunk.SourceMetadata.Git.Line
			}
			got.lastEndsNewline = len(chunk.Data) > 0 && chunk.Data[len(chunk.Data)-1] == '\n'
		}
		resultCh <- got
	}()

	parser := nativeLogParser{
		ctx:         context.Background(),
		source:      s,
		repo:        repo,
		ch:          ch,
		commit:      &nativeCommit{hash: hashes[0]},
		bufferLimit: 1,
	}
	diff := io.MultiReader(
		strings.NewReader("diff --git a/large.txt b/large.txt\n--- a/large.txt\n+++ b/large.txt\n@@ -1 +1 @@\n+prefix\n@@ -2 +2 @@\n+"),
		io.LimitReader(nativeRepeatedByte('x'), maxBlobSize+1024),
		strings.NewReader(marker+"\n\\ No newline at end of file\n"),
	)
	parseErr := parser.parse(diff)
	close(ch)
	got := <-resultCh
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if !got.found {
		t.Fatalf("tail marker missing after %d chunks", got.chunks)
	}
	if got.markerLine != 2 {
		t.Fatalf("tail marker line=%d, want 2", got.markerLine)
	}
	if got.maxLen > maxDiffChunkSize {
		t.Fatalf("chunk size=%d, exceeds %d", got.maxLen, maxDiffChunkSize)
	}
	if got.lastEndsNewline {
		t.Fatal("no-newline marker left a trailing newline in the final chunk")
	}
}

type nativeRepeatedByte byte

func (b nativeRepeatedByte) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(b)
	}
	return len(p), nil
}

func TestChunks_NativeSkipsBinaryWithNULOutsideChangedHunk(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11DISTANTNUL_abcdefghijklmnopqrstuvwxyz0123456789"
	base := "\x00" + strings.Repeat("a", 2048) + "\n"
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{"payload.bin": base}, msg: "binary base"},
		{files: map[string]string{"payload.bin": base + secret + "\n"}, msg: "binary update"},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if chunk.SourceMetadata.Git.File == "payload.bin" || strings.Contains(string(chunk.Data), secret) {
			t.Fatalf("binary modification emitted: file=%q bytes=%d", chunk.SourceMetadata.Git.File, len(chunk.Data))
		}
	}
}

func TestChunks_NativeSkipsDeletedBinary(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{{
		files: map[string]string{"payload.bin": "\x00binary"},
		msg:   "add binary",
	}})
	if err := os.Remove(filepath.Join(repoPath, "payload.bin")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("git",
		"-c", "core.hooksPath="+os.DevNull,
		"-c", "commit.gpgsign=false",
		"-c", "user.name=Test",
		"-c", "user.email=test@example.com",
		"-C", repoPath,
		"commit", "-am", "delete binary",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("delete binary: %v: %s", err, out)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	if _, err := drain(t, s, 10*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestChunks_NativeSkipsBinaryWithControlCharacterPath(t *testing.T) {
	requireNativeGit(t)
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, true)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	putObject := func(value plumbing.EncodedObject) plumbing.Hash {
		t.Helper()
		hash, err := repo.Storer.SetEncodedObject(value)
		if err != nil {
			t.Fatalf("SetEncodedObject: %v", err)
		}
		return hash
	}

	blob := repo.Storer.NewEncodedObject()
	blob.SetType(plumbing.BlobObject)
	writer, err := blob.Writer()
	if err != nil {
		t.Fatalf("blob Writer: %v", err)
	}
	if _, err := writer.Write([]byte("binary\x00content")); err != nil {
		t.Fatalf("write blob: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close blob: %v", err)
	}
	blobHash := putObject(blob)

	tree := &object.Tree{Entries: []object.TreeEntry{{
		Name: "control" + string([]byte{0x1c}) + "path.bin",
		Mode: filemode.Regular,
		Hash: blobHash,
	}}}
	treeObject := repo.Storer.NewEncodedObject()
	if err := tree.Encode(treeObject); err != nil {
		t.Fatalf("encode tree: %v", err)
	}
	treeHash := putObject(treeObject)

	when := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	commit := &object.Commit{
		Author:       object.Signature{Name: "Test", Email: "test@example.com", When: when},
		Committer:    object.Signature{Name: "Test", Email: "test@example.com", When: when},
		Message:      "control character path",
		TreeHash:     treeHash,
		ParentHashes: nil,
	}
	commitObject := repo.Storer.NewEncodedObject()
	if err := commit.Encode(commitObject); err != nil {
		t.Fatalf("encode commit: %v", err)
	}
	commitHash := putObject(commitObject)
	branch := plumbing.NewBranchReferenceName("master")
	if err := repo.Storer.SetReference(plumbing.NewHashReference(branch, commitHash)); err != nil {
		t.Fatalf("set branch: %v", err)
	}
	if err := repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branch)); err != nil {
		t.Fatalf("set HEAD: %v", err)
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("binary file emitted %d chunks", len(got))
	}
}

func TestParseNativePatchPathIgnoresTimestampSeparator(t *testing.T) {
	got, isNull, err := parseNativePatchPath([]byte("\"b/path with space.svg\"\t\n"), "b/")
	if err != nil {
		t.Fatal(err)
	}
	if isNull || got != "path with space.svg" {
		t.Fatalf("path=%q isNull=%v", got, isNull)
	}
}

func TestParseNativeCombinedRawPath(t *testing.T) {
	path, deleted, err := parseNativeCombinedRawPath([]byte("::100644 100644 100644 111 222 333 MM\t\"dir/merge result.txt\"\n"))
	if err != nil || deleted || path != "dir/merge result.txt" {
		t.Fatalf("path=%q deleted=%t err=%v", path, deleted, err)
	}
	path, deleted, err = parseNativeCombinedRawPath([]byte("::100644 100644 000000 111 222 000 DD\tremoved.txt\n"))
	if err != nil || !deleted || path != "removed.txt" {
		t.Fatalf("deleted path=%q deleted=%t err=%v", path, deleted, err)
	}
}

func TestNativeCombinedPatchKeepsOnlyResolutionAdds(t *testing.T) {
	start, ok := nativeCombinedHunkStart([]byte("@@@ -10,2 -20,3 +30,4 @@@\n"), 2)
	if !ok || start != 30 {
		t.Fatalf("start=%d ok=%v", start, ok)
	}

	tests := []struct {
		line string
		want string
	}{
		{"  shared\n", " shared\n"},
		{"+ from-first-parent\n", "\x01from-first-parent\n"},
		{" +from-second-parent\n", "\x01from-second-parent\n"},
		{"++merge-resolution\n", "+merge-resolution\n"},
		{"- removed-from-first\n", "-removed-from-first\n"},
	}
	for _, tt := range tests {
		got, err := nativeCombinedResultLine([]byte(tt.line), 2)
		if err != nil {
			t.Fatalf("%q: %v", tt.line, err)
		}
		if string(got) != tt.want {
			t.Fatalf("%q => %q, want %q", tt.line, got, tt.want)
		}
	}

	parser := nativeLogParser{inHunk: true, hunk: nativeHunk{newLine: 30}}
	if err := parser.consumeLine([]byte{nativeOmittedResultLine, 'x', '\n'}); err != nil {
		t.Fatal(err)
	}
	if parser.hunk.newLine != 31 || len(parser.hunk.data) != 0 || parser.hunk.hasAdd {
		t.Fatalf("omitted result line changed hunk content: %+v", parser.hunk)
	}
}

func TestChunks_NativeDisablesSignatureVerificationProgram(t *testing.T) {
	requireNativeGit(t)
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"base.txt": "base\n"}, msg: "base"}})
	key := filepath.Join(t.TempDir(), "signing-key")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	for _, setting := range [][2]string{{"user.name", "Test"}, {"user.email", "test@example.com"}, {"gpg.format", "ssh"}, {"user.signingKey", key}} {
		if out, err := exec.Command("git", "-C", repoPath, "config", setting[0], setting[1]).CombinedOutput(); err != nil {
			t.Fatalf("git config %s: %v: %s", setting[0], err, out)
		}
	}
	if err := os.WriteFile(filepath.Join(repoPath, "signed.txt"), []byte("signed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("git", "-C", repoPath, "add", "signed.txt").CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if out, err := exec.Command("git", "-c", "core.hooksPath="+os.DevNull, "-C", repoPath, "commit", "-S", "-m", "signed").CombinedOutput(); err != nil {
		t.Fatalf("git signed commit: %v: %s", err, out)
	}
	marker := filepath.Join(t.TempDir(), "signature-program-ran")
	program := filepath.Join(t.TempDir(), "signature-program")
	if err := os.WriteFile(program, []byte("#!/bin/sh\n: > \"$MARKER_PATH\"\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MARKER_PATH", marker)
	for _, setting := range [][2]string{{"log.showSignature", "true"}, {"gpg.ssh.program", program}} {
		if out, err := exec.Command("git", "-C", repoPath, "config", setting[0], setting[1]).CombinedOutput(); err != nil {
			t.Fatalf("git config %s: %v: %s", setting[0], err, out)
		}
	}

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	if _, err := drain(t, s, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("configured signature program executed: %v", err)
	}
}

func TestChunks_NativeSkipsEverySegmentOfBinaryFile(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11LATEBINARY_abcdefghijklmnopqrstuvwxyz0123456789"
	data := "\x00" + strings.Repeat("a", maxDiffChunkSize+1024) + secret
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"payload.bin": data}, msg: "binary"}})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, chunk := range got {
		if chunk.SourceMetadata.Git.File == "payload.bin" || strings.Contains(string(chunk.Data), secret) {
			t.Fatalf("binary segment emitted: file=%q bytes=%d", chunk.SourceMetadata.Git.File, len(chunk.Data))
		}
	}
}

func TestChunks_NativeStreamsOptInBinaryAndArchiveArtifacts(t *testing.T) {
	requireNativeGit(t)
	const binaryMarker = "native-binary-marker"
	const archiveMarker = "native-archive-marker"
	var zipped bytes.Buffer
	zw := zip.NewWriter(&zipped)
	entry, err := zw.Create("inside.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(archiveMarker)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{
		"payload.bin": "\x00" + binaryMarker,
		"payload.zip": zipped.String(),
	}, msg: "artifacts"}})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath, IncludeGitArchives: true, IncludeGitBinaries: true})
	if !s.nativeFastPathEligible(1) {
		t.Fatal("artifact coverage unexpectedly disabled the native history stream")
	}
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	var binaryFound, archiveFound bool
	for _, chunk := range got {
		binaryFound = binaryFound || strings.Contains(string(chunk.Data), binaryMarker)
		archiveFound = archiveFound || strings.Contains(string(chunk.Data), archiveMarker)
	}
	if !binaryFound || !archiveFound {
		t.Fatalf("native artifact coverage: binary=%t archive=%t", binaryFound, archiveFound)
	}
}

func TestChunks_NativeDisablesExternalDiff(t *testing.T) {
	requireNativeGit(t)
	const secret = "github_pat_11NOEXTDIFF_abcdefghijklmnopqrstuvwxyz0123456789"
	marker := filepath.Join(t.TempDir(), "external-diff-ran")
	repoPath, _ := buildRepo(t, []commitSpec{
		{files: map[string]string{".gitattributes": "secret.txt diff=hostile\n", "secret.txt": "safe\n"}, msg: "base"},
		{files: map[string]string{".gitattributes": "secret.txt diff=hostile\n", "secret.txt": "safe\n" + secret + "\n"}, msg: "secret"},
	})
	if out, err := exec.Command("git", "-C", repoPath, "config", "diff.hostile.command", "touch "+marker).CombinedOutput(); err != nil {
		t.Fatalf("git config: %v: %s", err, out)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, chunk := range got {
		found = found || strings.Contains(string(chunk.Data), secret)
	}
	if !found {
		t.Fatal("secret missing with external diff configured")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("external diff executed: %v", err)
	}
}

func TestChunks_NativeUnsupportedFallsBackBeforeEmission(t *testing.T) {
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "alpha"}, msg: "base"}})
	binDir := t.TempDir()
	fakeGit := filepath.Join(binDir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\necho \"error: unknown option 'diff-merges'\" >&2\nexit 129\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatalf("fallback Chunks: %v", err)
	}
	if len(got) != 1 || string(got[0].Data) != "alpha" {
		t.Fatalf("fallback chunks=%#v", got)
	}
	if len(s.IncrementalState()) == 0 {
		t.Fatal("successful fallback did not checkpoint")
	}
}

func TestChunks_NativeProbeRuntimeFailureIsDegraded(t *testing.T) {
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "alpha"}, msg: "base"}})
	binDir := t.TempDir()
	fakeGit := filepath.Join(binDir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\necho 'fatal: permission denied' >&2\nexit 128\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir)

	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("chunks=%d err=%v", len(got), err)
	}
	if len(got) != 0 {
		t.Fatalf("runtime probe failure silently fell back: %#v", got)
	}
	if state := s.IncrementalState(); len(state) != 0 {
		t.Fatalf("runtime probe failure checkpointed: %s", state)
	}
}

func TestChunks_NativeClockSkewUsesCausalOldestFirst(t *testing.T) {
	requireNativeGit(t)
	parentTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	childTime := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	repoPath, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"parent.txt": "parent"}, msg: "parent", when: parentTime},
		{files: map[string]string{"child.txt": "child"}, msg: "child", when: childTime},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].SourceMetadata.Git.Commit != hashes[0] || got[1].SourceMetadata.Git.Commit != hashes[1] {
		t.Fatalf("clock-skew order=%v, want causal parent then child", commitOrder(got))
	}
}

func TestChunks_NativeMergeScansResolutionWithoutRepeatingBranch(t *testing.T) {
	requireNativeGit(t)
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cBase := commitOn(t, repo, map[string]string{"base.txt": "base\n"}, "base", base)
	checkoutNewBranch(t, repo, "feature")
	cFeature := commitOn(t, repo, map[string]string{"feature.txt": "branch-only\n"}, "feature", base.Add(time.Minute))

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		if err2 := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err2 != nil {
			t.Fatalf("checkout default branch: %v / %v", err, err2)
		}
	}
	cMain := commitOn(t, repo, map[string]string{"main.txt": "main-only\n"}, "main", base.Add(2*time.Minute))
	cMerge := commitMerge(t, repo, map[string]string{
		"feature.txt":    "branch-only\n",
		"resolution.txt": "merge-only\n",
	}, "merge", base.Add(3*time.Minute), plumbing.NewHash(cMain), plumbing.NewHash(cFeature))

	s := &Source{}
	mustInit(t, s, Config{Repo: dir})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]int)
	for _, chunk := range got {
		seen[chunk.SourceMetadata.Git.File]++
		if chunk.SourceMetadata.Git.File == "resolution.txt" && chunk.SourceMetadata.Git.Commit != cMerge {
			t.Fatalf("resolution attributed to %s, want merge %s", chunk.SourceMetadata.Git.Commit, cMerge)
		}
	}
	for _, file := range []string{"base.txt", "feature.txt", "main.txt", "resolution.txt"} {
		if seen[file] != 1 {
			t.Fatalf("%s emitted %d times, want once; base=%s chunks=%v", file, seen[file], cBase, filesOf(got))
		}
	}

	parity := &Source{}
	mustInit(t, parity, Config{Repo: dir, SkipMergeCommits: true})
	got, err = drain(t, parity, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	seen = make(map[string]int)
	for _, chunk := range got {
		seen[chunk.SourceMetadata.Git.File]++
	}
	if seen["resolution.txt"] != 0 {
		t.Fatalf("merge-only resolution emitted in parity mode: %v", filesOf(got))
	}
	for _, file := range []string{"base.txt", "feature.txt", "main.txt"} {
		if seen[file] != 1 {
			t.Fatalf("%s emitted %d times in parity mode, want once; chunks=%v", file, seen[file], filesOf(got))
		}
	}

	compatible := &Source{}
	mustInit(t, compatible, Config{Repo: dir, TrufflehogCompatible: true})
	got, err = drain(t, compatible, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if filesOf(got)["resolution.txt"] {
		t.Fatalf("merge-only resolution emitted in trufflehog-compatible mode: %v", filesOf(got))
	}

	fallback := &Source{}
	mustInit(t, fallback, Config{Repo: dir, SkipMergeCommits: true, IncludeCommitMetadata: true})
	got, err = drain(t, fallback, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	mergeMetadata := false
	for _, chunk := range got {
		meta := chunk.SourceMetadata.Git
		if meta.File == "resolution.txt" {
			t.Fatalf("fallback emitted merge-only resolution in parity mode: %v", filesOf(got))
		}
		if meta.Commit == cMerge && strings.HasPrefix(meta.File, "commit:metadata/") {
			mergeMetadata = true
		}
	}
	if !mergeMetadata {
		t.Fatal("fallback parity mode dropped requested merge metadata")
	}
}

func TestParseNativeMergeResultsStreamsFragmentedAddedLine(t *testing.T) {
	repoPath, hashes := buildRepo(t, []commitSpec{{
		files: map[string]string{"large.txt": "text\n"},
		msg:   "large text",
	}})
	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	ch := make(chan *sources.Chunk, 1)
	const marker = "merge-tail-marker"
	parent1 := strings.Repeat("1", 40)
	parent2 := strings.Repeat("2", 40)
	zero := strings.Repeat("0", 40)
	record := string(nativeRecordSeparator) + hashes[0] + string(nativeFieldSeparator) +
		parent1 + " " + parent2 + string(nativeFieldSeparator) +
		"Test" + string(nativeFieldSeparator) +
		"test@example.com" + string(nativeFieldSeparator) +
		"2026-05-01T00:00:00Z" + string(nativeFieldSeparator) +
		"merge" + string(nativeFieldSeparator) + "\n"
	diff := io.MultiReader(
		strings.NewReader(record+
			"::100644 100644 100644 "+zero+" "+zero+" "+zero+" MM\tlarge.txt\n"+
			"diff --cc large.txt\n--- a/large.txt\n+++ b/large.txt\n"+
			"@@@ -1,1 -1,1 +1,1 @@@\n++"),
		io.LimitReader(nativeRepeatedByte('x'), 300<<10),
		strings.NewReader(marker+"\n"),
	)
	if err := s.parseNativeMergeResults(context.Background(), repo, "", diff, ch); err != nil {
		t.Fatal(err)
	}
	close(ch)
	chunk := <-ch
	if chunk == nil || !bytes.Contains(chunk.Data, []byte(marker)) {
		t.Fatal("fragmented combined line lost its tail marker")
	}
}

func TestChunks_NativeSinceFilterTraversesSkewedHistory(t *testing.T) {
	requireNativeGit(t)
	recent := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	old := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	repoPath, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"first.txt": "first"}, msg: "recent ancestor", when: recent},
		{files: map[string]string{"old.txt": "old"}, msg: "skewed old middle", when: old},
		{files: map[string]string{"last.txt": "last"}, msg: "recent child", when: recent.Add(time.Minute)},
	})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath, Since: "2025-01-01T00:00:00Z"})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	order := commitOrder(got)
	if !slices.Equal(order, []string{hashes[0], hashes[2]}) {
		t.Fatalf("since-as-filter order=%v, want recent commits across old middle commit", order)
	}
}

func TestChunks_NativeCancellationDoesNotCheckpoint(t *testing.T) {
	requireNativeGit(t)
	repoPath, _ := buildRepo(t, []commitSpec{{files: map[string]string{"a.txt": "alpha"}, msg: "base"}})
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan *sources.Chunk)
	errCh := make(chan error, 1)
	go func() { errCh <- s.Chunks(ctx, ch) }()
	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("native walk did not cancel")
	}
	if state := s.IncrementalState(); len(state) != 0 {
		t.Fatalf("canceled walk checkpointed: %s", state)
	}
}

func TestChunks_NativeDropsMissingIncrementalStop(t *testing.T) {
	requireNativeGit(t)
	oldRepo, _ := buildRepo(t, []commitSpec{{files: map[string]string{"old.txt": "old\n"}, msg: "old history"}})
	first := &Source{}
	mustInit(t, first, Config{Repo: oldRepo})
	if _, err := drain(t, first, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	previous := first.IncrementalState()
	if len(previous) == 0 {
		t.Fatal("first scan did not checkpoint")
	}

	const secret = "github_pat_11FORCEPUSH_abcdefghijklmnopqrstuvwxyz0123456789"
	newRepo, hashes := buildRepo(t, []commitSpec{{files: map[string]string{"new.txt": secret + "\n"}, msg: "rewritten history"}})
	second := &Source{}
	mustInit(t, second, Config{Repo: newRepo})
	if err := second.SetIncrementalState(previous); err != nil {
		t.Fatal(err)
	}
	got, err := drain(t, second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(string(got[0].Data), secret) {
		t.Fatalf("rewritten history chunks=%#v", got)
	}
	next := second.IncrementalState()
	if !strings.Contains(string(next), hashes[0]) || string(next) == string(previous) {
		t.Fatalf("rewritten history state=%s previous=%s", next, previous)
	}
}

func TestReadNativeLineBoundsAndDrains(t *testing.T) {
	reader := bufio.NewReaderSize(strings.NewReader(strings.Repeat("x", 128)+"\nnext\n"), 8)
	line, truncated, err := readNativeLine(reader, 16)
	if err != nil || !truncated || len(line) != 16 {
		t.Fatalf("first line len=%d truncated=%t err=%v", len(line), truncated, err)
	}
	line, truncated, err = readNativeLine(reader, 16)
	if err != nil || truncated || string(line) != "next\n" {
		t.Fatalf("second line=%q truncated=%t err=%v", line, truncated, err)
	}
}

func TestNativeFilePatchBoundsSegmentMetadata(t *testing.T) {
	parser := nativeLogParser{}
	for i := 0; i <= nativeSegmentLimit; i++ {
		if err := parser.appendFile([]byte("x"), i+1); err != nil {
			t.Fatal(err)
		}
	}
	file := parser.file
	if !file.overSegmentLimit || len(file.segments) != 0 {
		t.Fatalf("overSegmentLimit=%t segments=%d", file.overSegmentLimit, len(file.segments))
	}
}

func TestNativeLogParserBoundsRawPathMetadata(t *testing.T) {
	parser := nativeLogParser{rawPaths: make([]string, nativePathLimit)}
	if err := parser.consumeLine([]byte(":100644 100644 a b M\tfile.txt\n")); err == nil {
		t.Fatal("raw path entry limit was not enforced")
	}
	parser = nativeLogParser{rawPathBytes: maxBlobSize}
	if err := parser.consumeLine([]byte(":100644 100644 a b M\tfile.txt\n")); err == nil {
		t.Fatal("raw path byte limit was not enforced")
	}
}

func TestNativeFastPathFallsBackForMultiHeadMaxDepth(t *testing.T) {
	s := &Source{maxDepth: 10, includeCommitMetadata: true, includeGitArchives: true, includeGitBinaries: true}
	if s.nativeFastPathEligible(2) {
		t.Fatal("multi-head max-depth walk must use the canonical Go traversal")
	}
	if !s.nativeFastPathEligible(1) {
		t.Fatal("production coverage options should remain native-eligible for a single head")
	}
}

func TestChunks_NativeProductionOptionsRemainIncremental(t *testing.T) {
	requireNativeGit(t)
	const oldMarker = "old-history-marker"
	const newMarker = "new-history-marker"
	repoPath, _ := buildRepo(t, []commitSpec{{
		files: map[string]string{"old.txt": oldMarker + "\n"},
		msg:   "old commit",
	}})
	productionConfig := Config{
		Repo:                  repoPath,
		AllBranches:           true,
		TrufflehogCompatible:  true,
		IncludeCommitMetadata: true,
		IncludeGitArchives:    true,
		IncludeGitBinaries:    true,
	}
	first := &Source{}
	mustInit(t, first, productionConfig)
	if !first.nativeFastPathEligible(1) {
		t.Fatal("production options did not select the native path")
	}
	if _, err := drain(t, first, 10*time.Second); err != nil {
		t.Fatal(err)
	}
	previous := first.IncrementalState()
	if len(previous) == 0 {
		t.Fatal("first production-options scan did not checkpoint")
	}

	repo, err := gogit.PlainOpen(repoPath)
	if err != nil {
		t.Fatal(err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoPath, "new.txt"), []byte(newMarker+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add("new.txt"); err != nil {
		t.Fatal(err)
	}
	newHash, err := wt.Commit("new commit", &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
		Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)},
	})
	if err != nil {
		t.Fatal(err)
	}

	second := &Source{}
	mustInit(t, second, productionConfig)
	if err := second.SetIncrementalState(previous); err != nil {
		t.Fatal(err)
	}
	got, err := drain(t, second, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	newFound := false
	for _, chunk := range got {
		if chunk.SourceMetadata.Git == nil || chunk.SourceMetadata.Git.Commit != newHash.String() {
			t.Fatalf("incremental scan re-emitted an old commit: %+v", chunk.SourceMetadata.Git)
		}
		data := string(chunk.Data)
		if strings.Contains(data, oldMarker) {
			t.Fatal("incremental scan re-emitted old content")
		}
		newFound = newFound || strings.Contains(data, newMarker)
	}
	if !newFound {
		t.Fatal("incremental scan missed new content")
	}
	if bytes.Equal(second.IncrementalState(), previous) {
		t.Fatal("incremental checkpoint did not advance")
	}
}

func requireNativeGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("native git unavailable")
	}
}

func commitOrder(chunks []*sources.Chunk) []string {
	order := make([]string, 0, len(chunks))
	for _, chunk := range chunks {
		order = append(order, chunk.SourceMetadata.Git.Commit)
	}
	return order
}
