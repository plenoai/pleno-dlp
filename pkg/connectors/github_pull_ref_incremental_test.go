package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubIncrementalPullRefsInvalidatePushedAtSkip(t *testing.T) {
	fixture, _ := buildFixtureRepo(t)
	repo, err := gogit.PlainOpen(fixture)
	if err != nil {
		t.Fatal(err)
	}
	prHead := commitOnTemporaryGitHubTestBranch(t, repo, fixture, "pr-a", "pr-a.txt", "first")
	setGitHubTestRef(t, repo, "refs/pull/7/head", prHead)

	const pushedAt = "2026-08-01T00:00:00Z"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/widget" {
			http.NotFound(w, r)
			return
		}
		ref := githubRepoRef{Name: "widget", PushedAt: pushedAt, Visibility: "private"}
		ref.Owner.Login = "acme"
		writeJSON(t, w, ref)
	}))
	t.Cleanup(srv.Close)

	var clones atomic.Int64
	oldObserver := githubCloneBytesObserver
	githubCloneBytesObserver = func(string, int64) { clones.Add(1) }
	t.Cleanup(func() { githubCloneBytesObserver = oldObserver })

	run := func(previous string) (*githubIncrementalState, error) {
		t.Helper()
		cfg := Config{
			"token":              "test-token",
			"repo":               "acme/widget",
			"api_base":           srv.URL,
			"clone_url_template": fixture,
		}
		if previous != "" {
			cfg[configKeyIncrementalPreviousState] = previous
		}
		err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil })
		state, stateErr := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
		if stateErr != nil {
			t.Fatalf("load next state: %v", stateErr)
		}
		return state, err
	}
	history := func(state *githubIncrementalState) githubRepoIncrementalState {
		t.Helper()
		return state.Surfaces["repository-history"]["acme/widget"]
	}
	raw := func(state *githubIncrementalState) string {
		t.Helper()
		data, err := json.Marshal(state)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}

	baseline, err := run("")
	if err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	baselineRepo := history(baseline)
	if got := baselineRepo.PullRefHeads["refs/pull/7/head"]; got != prHead.String() {
		t.Fatalf("baseline pull ref = %q, want %s; state=%+v", got, prHead, baselineRepo)
	}
	if clones.Load() != 1 {
		t.Fatalf("baseline clones = %d, want 1", clones.Load())
	}

	identical, err := run(raw(baseline))
	if err != nil {
		t.Fatalf("identical scan: %v", err)
	}
	if clones.Load() != 1 {
		t.Fatalf("identical pull refs triggered clone; clones=%d", clones.Load())
	}

	// Ref advertisement comparison is deliberately limited to exact GitHub
	// pull-request refs. Pseudo refs must not invalidate the unchanged skip or
	// enter its checkpoint snapshot.
	main, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	setGitHubTestRef(t, repo, "refs/notes/review", main.Hash())
	setGitHubTestRef(t, repo, plumbing.ReferenceName("refs/replace/"+main.Hash().String()), prHead)
	pseudoOnly, err := run(raw(identical))
	if err != nil {
		t.Fatalf("pseudo-ref scan: %v", err)
	}
	if clones.Load() != 1 {
		t.Fatalf("pseudo refs triggered clone; clones=%d", clones.Load())
	}
	if len(history(pseudoOnly).PullRefHeads) != 1 {
		t.Fatalf("pseudo refs entered pull snapshot: %v", history(pseudoOnly).PullRefHeads)
	}

	updatedHead := commitOnTemporaryGitHubTestBranch(t, repo, fixture, "pr-b", "pr-b.txt", "second")
	setGitHubTestRef(t, repo, "refs/pull/7/head", updatedHead)
	updated, err := run(raw(pseudoOnly))
	if err != nil {
		t.Fatalf("updated pull ref scan: %v", err)
	}
	if clones.Load() != 2 || history(updated).PullRefHeads["refs/pull/7/head"] != updatedHead.String() {
		t.Fatalf("updated ref did not invalidate skip: clones=%d refs=%v", clones.Load(), history(updated).PullRefHeads)
	}

	setGitHubTestRef(t, repo, "refs/pull/7/merge", updatedHead)
	added, err := run(raw(updated))
	if err != nil {
		t.Fatalf("added pull ref scan: %v", err)
	}
	if clones.Load() != 3 || len(history(added).PullRefHeads) != 2 {
		t.Fatalf("added ref did not invalidate skip: clones=%d refs=%v", clones.Load(), history(added).PullRefHeads)
	}

	if err := repo.Storer.RemoveReference("refs/pull/7/head"); err != nil {
		t.Fatal(err)
	}
	deleted, err := run(raw(added))
	if err != nil {
		t.Fatalf("deleted pull ref scan: %v", err)
	}
	deletedRepo := history(deleted)
	if clones.Load() != 4 || len(deletedRepo.PullRefHeads) != 1 || deletedRepo.PullRefHeads["refs/pull/7/merge"] != updatedHead.String() {
		t.Fatalf("deleted ref did not invalidate skip: clones=%d refs=%v", clones.Load(), deletedRepo.PullRefHeads)
	}

	// A failed advertisement probe must never carry the old snapshot as proof
	// that the repository is unchanged. The fallback clone also fails here, so
	// the completed history checkpoint must remain unchanged and degradation is
	// surfaced to the caller.
	unavailable := filepath.Join(filepath.Dir(fixture), filepath.Base(fixture)+"-unavailable")
	if err := os.Rename(fixture, unavailable); err != nil {
		t.Fatal(err)
	}
	failed, err := run(raw(deleted))
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) {
		t.Fatalf("probe+clone failure = %v, want degraded coverage", err)
	}
	failedRepo := history(failed)
	if !maps.Equal(failedRepo.PullRefHeads, deletedRepo.PullRefHeads) ||
		!maps.Equal(failedRepo.RefHeads, deletedRepo.RefHeads) ||
		failedRepo.PushedAt != deletedRepo.PushedAt {
		t.Fatalf("failed probe advanced history checkpoint: before=%+v after=%+v", deletedRepo, failedRepo)
	}
}

func commitOnTemporaryGitHubTestBranch(t *testing.T, repo *gogit.Repository, dir, branch, file, content string) plumbing.Hash {
	t.Helper()
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	original, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	branchRef := plumbing.NewBranchReferenceName(branch)
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: branchRef, Create: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := wt.Add(file); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(len(content)) * time.Minute)
	hash, err := wt.Commit(branch, &gogit.CommitOptions{
		Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: when},
		Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: when},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{Branch: original.Name()}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Storer.RemoveReference(branchRef); err != nil {
		t.Fatal(err)
	}
	return hash
}

func setGitHubTestRef(t *testing.T, repo *gogit.Repository, name plumbing.ReferenceName, hash plumbing.Hash) {
	t.Helper()
	if err := repo.Storer.SetReference(plumbing.NewHashReference(name, hash)); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubPullRefAdvertisementFiltersPseudoRefs(t *testing.T) {
	const (
		head  = "1111111111111111111111111111111111111111"
		merge = "2222222222222222222222222222222222222222"
	)
	raw := head + "\trefs/pull/12/head\n" +
		merge + "\trefs/pull/12/merge\n" +
		head + "\trefs/notes/review\n" +
		head + "\trefs/replace/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		head + "\trefs/pull/not-a-number/head\n"
	got, err := parseGitHubPullRefAdvertisement(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"refs/pull/12/head": head, "refs/pull/12/merge": merge}
	if !maps.Equal(got, want) {
		t.Fatalf("pull refs = %v, want %v", got, want)
	}
	if _, err := parseGitHubPullRefAdvertisement("not-a-hash\trefs/pull/12/head\n"); err == nil {
		t.Fatal("malformed advertised pull-ref hash was accepted")
	}
}

func TestGitHubPullRefAdvertisementLimits(t *testing.T) {
	const hash = "1111111111111111111111111111111111111111"
	line := hash + "\trefs/pull/1/head"

	t.Run("bytes", func(t *testing.T) {
		buffer := githubBoundedBuffer{limit: 5}
		if n, err := buffer.Write([]byte("abc")); err != nil || n != 3 {
			t.Fatalf("first bounded write = (%d, %v)", n, err)
		}
		if n, err := buffer.Write([]byte("def")); err != nil || n != 3 || buffer.Len() != 5 || !buffer.exceeded {
			t.Fatalf("overflow bounded write = (%d, %v), len=%d exceeded=%v", n, err, buffer.Len(), buffer.exceeded)
		}
		exact := githubBoundedBuffer{limit: 5}
		_, _ = exact.Write([]byte("ab"))
		_, _ = exact.Write([]byte("cde"))
		if exact.Len() != 5 || exact.exceeded {
			t.Fatalf("exact bounded write len=%d exceeded=%v", exact.Len(), exact.exceeded)
		}
	})

	t.Run("line bytes", func(t *testing.T) {
		if _, err := parseGitHubPullRefAdvertisementReader(strings.NewReader(line), 8, 10, 10); err == nil {
			t.Fatal("oversized advertisement line was accepted")
		}
	})

	t.Run("lines", func(t *testing.T) {
		raw := line + "\n" + hash + "\trefs/pull/2/head\n"
		if _, err := parseGitHubPullRefAdvertisementReader(strings.NewReader(raw), 256, 1, 10); err == nil {
			t.Fatal("excess advertisement lines were accepted")
		}
		if _, err := parseGitHubPullRefAdvertisementReader(strings.NewReader("\n\n"), 256, 1, 10); err == nil {
			t.Fatal("excess blank advertisement lines were accepted")
		}
	})

	t.Run("pull refs", func(t *testing.T) {
		raw := line + "\n" + hash + "\trefs/pull/2/head\n"
		if _, err := parseGitHubPullRefAdvertisementReader(strings.NewReader(raw), 256, 10, 1); err == nil {
			t.Fatal("excess advertised pull refs were accepted")
		}
	})

	t.Run("conflicting duplicate", func(t *testing.T) {
		raw := line + "\n2222222222222222222222222222222222222222\trefs/pull/1/head\n"
		if _, err := parseGitHubPullRefAdvertisementReader(strings.NewReader(raw), 256, 10, 10); err == nil {
			t.Fatal("conflicting duplicate pull ref was accepted")
		}
	})
}

func TestFilterGitHubPullRefsLimitsReturnedAndSelectedRefs(t *testing.T) {
	hash := plumbing.NewHash("1111111111111111111111111111111111111111")
	refs := []*plumbing.Reference{
		plumbing.NewHashReference("refs/heads/main", hash),
		plumbing.NewHashReference("refs/pull/1/head", hash),
		plumbing.NewHashReference("refs/pull/2/head", hash),
	}
	if _, err := filterGitHubPullRefs(refs, 2, 1_000, 256, 10, 1_000); err == nil {
		t.Fatal("excess go-git returned refs were accepted")
	}
	if _, err := filterGitHubPullRefs(refs, 10, 1_000, 256, 1, 1_000); err == nil {
		t.Fatal("excess go-git pull refs were accepted")
	}
	if _, err := filterGitHubPullRefs(refs[:1], 10, 1_000, 4, 10, 1_000); err == nil {
		t.Fatal("oversized go-git ref name was accepted")
	}
	if _, err := filterGitHubPullRefs(refs[:2], 10, 10, 256, 10, 1_000); err == nil {
		t.Fatal("excess aggregate go-git ref-name bytes were accepted")
	}
	if _, err := filterGitHubPullRefs(refs[1:], 10, 1_000, 256, 10, 32); err == nil {
		t.Fatal("excess go-git pull-ref snapshot bytes were accepted")
	}
	symbolic := plumbing.NewSymbolicReference("refs/pull/3/head", "refs/heads/main")
	if _, err := filterGitHubPullRefs([]*plumbing.Reference{symbolic}, 10, 1_000, 256, 10, 1_000); err == nil {
		t.Fatal("symbolic go-git pull ref was accepted")
	}
	conflicting := []*plumbing.Reference{
		plumbing.NewHashReference("refs/pull/3/head", hash),
		plumbing.NewHashReference("refs/pull/3/head", plumbing.NewHash("2222222222222222222222222222222222222222")),
	}
	if _, err := filterGitHubPullRefs(conflicting, 10, 1_000, 256, 10, 1_000); err == nil {
		t.Fatal("conflicting duplicate go-git pull ref was accepted")
	}
}

func TestNativeGitPullRefArgsLimitAdvertisementPatterns(t *testing.T) {
	got := nativeGitPullRefArgs("https://github.com/acme/widget.git")
	want := []string{
		"ls-remote", "--refs", "--", "https://github.com/acme/widget.git",
		"refs/pull/*/head", "refs/pull/*/merge",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("native pull-ref args = %v, want %v", got, want)
	}
}

func TestProbeGitHubPullRefsGoGitFiltersPseudoRefs(t *testing.T) {
	fixture, _ := buildFixtureRepo(t)
	repo, err := gogit.PlainOpen(fixture)
	if err != nil {
		t.Fatal(err)
	}
	head, err := repo.Head()
	if err != nil {
		t.Fatal(err)
	}
	setGitHubTestRef(t, repo, "refs/pull/9/head", head.Hash())
	setGitHubTestRef(t, repo, "refs/notes/review", head.Hash())
	setGitHubTestRef(t, repo, plumbing.ReferenceName("refs/replace/"+head.Hash().String()), head.Hash())

	got, err := probeGitHubPullRefsGoGit(context.Background(), fixture, "")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"refs/pull/9/head": head.Hash().String()}
	if !maps.Equal(got, want) {
		t.Fatalf("go-git pull refs = %v, want %v", got, want)
	}
}
