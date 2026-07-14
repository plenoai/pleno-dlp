package git

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"

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
	args := s.nativeLogArgs([]plumbing.Hash{start}, []plumbing.Hash{stop})

	for _, want := range []string{
		"--patch", "--root", "--reverse", "--topo-order", "--full-history",
		"--no-show-signature", "--raw", "--abbrev=40", "--no-renames",
		"--no-ext-diff", "--no-textconv", "--no-indent-heuristic",
		"--inter-hunk-context=0", "--ignore-submodules=all",
		"--diff-algorithm=myers", "--diff-merges=first-parent", "--unified=3",
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
	var file nativeFilePatch
	for i := 0; i <= nativeSegmentLimit; i++ {
		file.append([]byte("x"), i+1)
	}
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
	s := &Source{maxDepth: 10}
	if s.nativeFastPathEligible(2) {
		t.Fatal("multi-head max-depth walk must use the canonical Go traversal")
	}
	if !s.nativeFastPathEligible(1) {
		t.Fatal("single-head max-depth walk should remain native-eligible")
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
