package git

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
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
		name             string
		skip, compatible bool
	}{{"skip-merges", true, false}, {"compatible", false, true}} {
		for _, clone := range []struct{ name, dir string }{{"complete", dir}, {"filtered", dst}} {
			t.Run(mode.name+"/"+clone.name, func(t *testing.T) {
				s := &Source{}
				mustInit(t, s, Config{Repo: clone.dir, SkipMergeCommits: mode.skip, TrufflehogCompatible: mode.compatible})
				got, err := drain(t, s, 10*time.Second)
				t.Logf("files=%v err=%v", filesOf(got), err)
				if err != nil {
					t.Fatal(err)
				}
				if filesOf(got)["resolution.txt"] {
					t.Fatal("merge-only content emitted despite omit-merge policy")
				}
			})
		}
	}
}
