package git

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestReviewLargeRetainedTextWithExcludedOmission(t *testing.T) {
	requireNativeGit(t)
	const marker = "review_retained_large_text_canary"
	src, _ := buildRepo(t, []commitSpec{{files: map[string]string{
		"retained.txt": marker + "\n" + strings.Repeat(strings.Repeat("x", 1023)+"\n", 51*1024),
		"omitted.bin":  strings.Repeat("\x00", 65<<20),
	}, msg: "large retained text and excluded omitted binary"}})
	dst := reviewClone(t, src, "blob:limit=62914561")
	hash := strings.TrimSpace(gitExec(t, src, "rev-parse", "HEAD:retained.txt"))
	cmd := exec.Command("git", "-C", dst, "cat-file", "-e", hash)
	cmd.Env = nativeGitEnv()
	if err := cmd.Run(); err != nil {
		t.Fatal("retained text must exist locally")
	}
	for _, c := range []struct{ name, dir string }{{"complete", src}, {"filtered", dst}} {
		t.Run(c.name, func(t *testing.T) {
			s := &Source{}
			mustInit(t, s, Config{Repo: c.dir, Exclude: []string{"omitted.bin"}})
			got, err := drain(t, s, 30*time.Second)
			found := false
			for _, chunk := range got {
				found = found || bytes.Contains(chunk.Data, []byte(marker))
			}
			t.Logf("chunks=%d marker=%v err=%v state=%s", len(got), found, err, s.IncrementalState())
			if err != nil {
				t.Fatal(err)
			}
			if !found {
				t.Fatal("locally retained scannable text was silently omitted")
			}
		})
	}
}

func TestReviewGoGitLargeAddedTextStreamsAndCancels(t *testing.T) {
	const marker = "review_go_git_large_added_boundary_marker"
	payload := bytes.Repeat([]byte{'x'}, int(maxBlobSize+maxDiffChunkSize)+len(marker))
	copy(payload[maxDiffChunkSize-4:], marker)
	repoPath, hashes := buildRepo(t, []commitSpec{{files: map[string]string{
		"large.txt": string(payload),
	}, msg: "large go-git addition"}})
	repo, err := openBoundedRepository(repoPath, 1)
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(plumbing.NewHash(hashes[0]))
	if err != nil {
		t.Fatal(err)
	}
	s := &Source{}
	mustInit(t, s, Config{Repo: repoPath})
	chunks := make(chan *sources.Chunk)
	var count, maxChunk int
	found := false
	done := make(chan struct{})
	go func() {
		defer close(done)
		for chunk := range chunks {
			count++
			if len(chunk.Data) > maxChunk {
				maxChunk = len(chunk.Data)
			}
			found = found || bytes.Contains(chunk.Data, []byte(marker))
		}
	}()
	if err := s.emitCommit(context.Background(), commit, chunks); err != nil {
		close(chunks)
		<-done
		t.Fatal(err)
	}
	close(chunks)
	<-done
	if !found {
		t.Fatal("large added text boundary canary was not emitted")
	}
	if count < 2 || maxChunk > maxDiffChunkSize {
		t.Fatalf("chunks=%d max_chunk=%d, want streamed chunks <= %d", count, maxChunk, maxDiffChunkSize)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancelChunks := make(chan *sources.Chunk)
	cancelDone := make(chan struct{})
	go func() {
		defer close(cancelDone)
		if _, ok := <-cancelChunks; ok {
			cancel()
		}
		for range cancelChunks {
		}
	}()
	cancelErr := s.emitCommit(canceled, commit, cancelChunks)
	close(cancelChunks)
	<-cancelDone
	if !errors.Is(cancelErr, context.Canceled) {
		t.Fatalf("canceled large added text error=%v, want context canceled", cancelErr)
	}
}

func TestReviewOfflineMultipleMergeResolutions(t *testing.T) {
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	commitOn(t, repo, map[string]string{"base.txt": "base\n"}, "base", base)
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	mainBranch := head.Name()
	checkoutNewBranch(t, repo, "feature-one")
	featureOne := commitOn(t, repo, map[string]string{"feature-one.txt": "one\n"}, "feature one", base.Add(time.Minute))
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: mainBranch}); err != nil {
		t.Fatal(err)
	}
	mainOne := commitOn(t, repo, map[string]string{"main-one.txt": "one\n"}, "main one", base.Add(2*time.Minute))
	mergeOne := commitMerge(t, repo, map[string]string{"resolution-one.txt": "one resolution\n"}, "merge one", base.Add(3*time.Minute), plumbing.NewHash(mainOne), plumbing.NewHash(featureOne))

	checkoutNewBranch(t, repo, "feature-two")
	featureTwo := commitOn(t, repo, map[string]string{"feature-two.txt": "two\n"}, "feature two", base.Add(4*time.Minute))
	wt, err = repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: mainBranch}); err != nil {
		t.Fatal(err)
	}
	mainTwo := commitOn(t, repo, map[string]string{"main-two.txt": "two\n"}, "main two", base.Add(5*time.Minute))
	mergeTwo := commitMerge(t, repo, map[string]string{"resolution-two.txt": "two resolution\n"}, "merge two", base.Add(6*time.Minute), plumbing.NewHash(mainTwo), plumbing.NewHash(featureTwo))

	dst := reviewClone(t, dir, "blob:limit=52428801")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"resolution-one.txt": mergeOne, "resolution-two.txt": mergeTwo}
	seen := map[string]int{}
	for _, chunk := range got {
		meta := chunk.SourceMetadata.Git
		if meta == nil {
			continue
		}
		if expected, ok := want[meta.File]; ok {
			seen[meta.File]++
			if meta.Commit != expected {
				t.Fatalf("%s attributed to %s, want %s", meta.File, meta.Commit, expected)
			}
		}
	}
	for file := range want {
		if seen[file] != 1 {
			t.Fatalf("%s emitted %d times, want once; files=%v", file, seen[file], filesOf(got))
		}
	}
}

func TestReviewManyMergeCommitsDoNotDeadlock(t *testing.T) {
	requireNativeGit(t)
	src, hashes := buildRepo(t, []commitSpec{
		{files: map[string]string{"a.txt": "base\n"}, msg: "base"},
		{files: map[string]string{"side.txt": "side\n"}, msg: "side"},
	})
	var input strings.Builder
	for i := 1; i <= 1100; i++ {
		parent := hashes[0]
		if i > 1 {
			parent = fmt.Sprintf(":%d", i-1)
		}
		fmt.Fprintf(&input, "commit refs/heads/merges\nmark :%d\ncommitter Review <review@example.com> %d +0000\ndata 5\nmerge\nfrom %s\nmerge %s\n\n", i, 1700000000+i, parent, hashes[1])
	}
	cmd := exec.Command("git", "-C", src, "fast-import", "--quiet")
	cmd.Stdin = strings.NewReader(input.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fast-import: %v %s", err, out)
	}
	gitExec(t, src, "symbolic-ref", "HEAD", "refs/heads/merges")
	dst := reviewClone(t, src, "blob:limit=52428801")
	s := &Source{}
	mustInit(t, s, Config{Repo: dst})
	got, err := drain(t, s, 10*time.Second)
	t.Logf("chunks=%d err=%v", len(got), err)
	if err != nil {
		t.Fatalf("merge commits must not deadlock enumeration: %v", err)
	}
}

func TestReviewPartialMergeOmissionFlags(t *testing.T) {
	requireNativeGit(t)
	dir := t.TempDir()
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	commitOn(t, repo, map[string]string{"base.txt": "base\n"}, "base", base)
	checkoutNewBranch(t, repo, "feature")
	feature := commitOn(t, repo, map[string]string{"feature.txt": "branch-only\n"}, "feature", base.Add(time.Minute))
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("master")}); err != nil {
		if err := wt.Checkout(&gogit.CheckoutOptions{Branch: plumbing.NewBranchReferenceName("main")}); err != nil {
			t.Fatal(err)
		}
	}
	main := commitOn(t, repo, map[string]string{"main.txt": "main-only\n"}, "main", base.Add(2*time.Minute))
	commitMerge(t, repo, map[string]string{"feature.txt": "branch-only\n", "resolution.txt": "merge-only\n"}, "merge", base.Add(3*time.Minute), plumbing.NewHash(main), plumbing.NewHash(feature))
	dst := reviewClone(t, dir, "blob:limit=52428801")
	for _, mode := range []struct {
		name                        string
		skip, compatible, wantMerge bool
	}{{"default", false, false, true}, {"skip-merges", true, false, false}, {"compatible", false, true, false}} {
		for _, clone := range []struct{ name, dir string }{{"complete", dir}, {"filtered", dst}} {
			t.Run(mode.name+"/"+clone.name, func(t *testing.T) {
				s := &Source{}
				mustInit(t, s, Config{Repo: clone.dir, SkipMergeCommits: mode.skip, TrufflehogCompatible: mode.compatible})
				got, err := drain(t, s, 10*time.Second)
				t.Logf("files=%v err=%v", filesOf(got), err)
				if err != nil {
					t.Fatal(err)
				}
				if gotMerge := filesOf(got)["resolution.txt"]; gotMerge != mode.wantMerge {
					t.Fatalf("resolution.txt emitted=%t, want %t", gotMerge, mode.wantMerge)
				}
			})
		}
	}
}
