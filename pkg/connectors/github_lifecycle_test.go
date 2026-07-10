package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubRepoConcurrency(t *testing.T) {
	for _, tc := range []struct {
		raw     string
		want    int
		wantErr bool
	}{
		{want: 1},
		{raw: "4", want: 4},
		{raw: "0", wantErr: true},
		{raw: "33", wantErr: true},
		{raw: "many", wantErr: true},
	} {
		got, err := githubRepoConcurrency(Config{"repo_concurrency": tc.raw})
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("repo_concurrency %q = (%d, %v), want (%d, err=%v)", tc.raw, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestGitHubFilterReposDefaultsAndReasons(t *testing.T) {
	ref := func(owner, name string, fork, archived bool) githubRepoRef {
		r := githubRepoRef{Name: name, Fork: fork, Archived: archived}
		r.Owner.Login = owner
		return r
	}
	repos := []githubRepoRef{
		ref("acme", "api", false, false),
		ref("acme", "fork", true, false),
		ref("acme", "old", false, true),
	}
	got, skipped, err := githubFilterRepos(Config{}, repos)
	if err != nil || len(got) != 3 || len(skipped) != 0 {
		t.Fatalf("default filter = (%v, %v, %v), want all repositories", got, skipped, err)
	}
	got, skipped, err = githubFilterRepos(Config{
		"include_forks": "false", "include_archived": "false",
		"include_repo_globs": "acme/*", "exclude_repo_globs": "*/api",
	}, repos)
	if err != nil || len(got) != 0 || skipped["fork"] != 1 || skipped["archived"] != 1 || skipped["excluded"] != 1 {
		t.Fatalf("filtered = (%v, %v, %v)", got, skipped, err)
	}
	if _, _, err := githubFilterRepos(Config{"include_repo_globs": "["}, repos); err == nil {
		t.Fatal("expected invalid glob error")
	}
}

func TestGitHubEnumerateReposExpandsMembersAndDeduplicates(t *testing.T) {
	ref := func(owner, name string) githubRepoRef {
		r := githubRepoRef{Name: name}
		r.Owner.Login = owner
		return r
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/orgs/acme/repos":
			writeJSON(t, w, []githubRepoRef{ref("acme", "core")})
		case "/orgs/acme/members":
			writeJSON(t, w, []githubMemberRef{{Login: "alice"}})
		case "/users/alice/repos":
			writeJSON(t, w, []githubRepoRef{ref("alice", "personal"), ref("acme", "core")})
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	repos, _, skipped, err := githubEnumerateRepos(context.Background(), newGitHubClient(srv.URL, staticGitHubToken("test")), Config{"expand_members": "true"}, "acme", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(repos) != 2 || skipped["duplicate"] != 1 {
		t.Fatalf("repos=%v skipped=%v", repos, skipped)
	}
}

func TestGitHubCommentsSince(t *testing.T) {
	now := time.Date(2026, 7, 10, 12, 0, 0, 0, time.FixedZone("JST", 9*60*60))
	got, err := githubCommentsSince(Config{"comments_timeframe_days": "7"}, now)
	if err != nil || got != "2026-07-03T03:00:00Z" {
		t.Fatalf("since = %q, %v", got, err)
	}
	if _, err := githubCommentsSince(Config{"comments_timeframe_days": "-1"}, now); err == nil {
		t.Fatal("expected negative timeframe error")
	}
}

func TestGitHubGitArtifactConfigRejectsMalformedAndHardCaps(t *testing.T) {
	for _, cfg := range []Config{
		{"git_artifact_max_bytes": "nope"}, {"git_artifact_max_bytes": "0"},
		{"git_artifact_max_bytes": "52428801"}, {"archive_timeout": "0s"},
		{"archive_timeout": "61s"}, {"archive_max_files": "10001"},
	} {
		if _, err := githubGitArtifactConfig(cfg); err == nil {
			t.Fatalf("cfg=%v accepted", cfg)
		}
	}
}

func TestRunGitHubSourceUnitsDeterministicFailureIsolation(t *testing.T) {
	units := []githubSourceUnit{
		{Surface: "repository-history", ID: "acme/slow"},
		{Surface: "repository-history", ID: "acme/fail"},
		{Surface: "repository-history", ID: "acme/fast"},
	}
	ready := make(chan struct{})
	releaseSlow := make(chan struct{})
	produce := func(_ context.Context, unit githubSourceUnit) githubUnitResult[string] {
		switch unit.ID {
		case "acme/slow":
			close(ready)
			<-releaseSlow
			return githubUnitResult[string]{State: "slow", Stats: githubUnitStats{CostItems: 1}}
		case "acme/fail":
			return githubUnitResult[string]{State: "carried", Err: errors.New("clone failed")}
		default:
			return githubUnitResult[string]{State: "fast", Stats: githubUnitStats{Skipped: "unchanged"}}
		}
	}
	var committed []string
	done := make(chan error, 1)
	go func() {
		_, err := runGitHubSourceUnits(context.Background(), units, 3, produce, func(_ int, result githubUnitResult[string]) error {
			committed = append(committed, result.Unit.Key()+"="+result.State)
			return nil
		})
		done <- err
	}()
	<-ready
	time.Sleep(10 * time.Millisecond)
	if len(committed) != 0 {
		t.Fatalf("later completions committed before the first unit: %v", committed)
	}
	close(releaseSlow)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := []string{
		"repository-history:acme/slow=slow",
		"repository-history:acme/fail=carried",
		"repository-history:acme/fast=fast",
	}
	if !reflect.DeepEqual(committed, want) {
		t.Fatalf("commit order = %v, want %v", committed, want)
	}
}

func TestRunGitHubSourceUnitsUnitDeadlineIsNotParentCancellation(t *testing.T) {
	units := []githubSourceUnit{{Surface: "issues", ID: "acme/one"}, {Surface: "issues", ID: "acme/two"}}
	stats, err := runGitHubSourceUnits(context.Background(), units, 2,
		func(_ context.Context, unit githubSourceUnit) githubUnitResult[int] {
			if unit.ID == "acme/one" {
				return githubUnitResult[int]{Err: context.DeadlineExceeded}
			}
			return githubUnitResult[int]{State: 2}
		},
		func(_ int, _ githubUnitResult[int]) error { return nil },
	)
	if err != nil || stats.Failed != 1 || stats.Completed != 1 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
}

func TestRunGitHubSourceUnitsBoundsConcurrency(t *testing.T) {
	units := make([]githubSourceUnit, 12)
	for i := range units {
		units[i] = githubSourceUnit{Surface: "repository-history", ID: fmt.Sprintf("acme/repo-%02d", i)}
	}
	var active atomic.Int64
	var peak atomic.Int64
	stats, err := runGitHubSourceUnits(context.Background(), units, 3, func(_ context.Context, _ githubSourceUnit) githubUnitResult[int] {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		return githubUnitResult[int]{Stats: githubUnitStats{CostItems: 1}}
	}, func(_ int, _ githubUnitResult[int]) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if got := peak.Load(); got != 3 {
		t.Fatalf("peak workers = %d, want 3", got)
	}
	if stats.Completed != len(units) || stats.CostItems != int64(len(units)) {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestRunGitHubSourceUnitsBoundsPendingWindowBehindSlowHead(t *testing.T) {
	units := make([]githubSourceUnit, 20)
	for i := range units {
		units[i] = githubSourceUnit{Surface: "repository-history", ID: fmt.Sprintf("acme/%02d", i)}
	}
	var started atomic.Int64
	headStarted := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := runGitHubSourceUnits(context.Background(), units, 3, func(_ context.Context, unit githubSourceUnit) githubUnitResult[int] {
			started.Add(1)
			if unit.ID == "acme/00" {
				close(headStarted)
				<-release
			}
			return githubUnitResult[int]{}
		}, func(int, githubUnitResult[int]) error { return nil })
		done <- err
	}()
	<-headStarted
	time.Sleep(20 * time.Millisecond)
	if got := started.Load(); got != 3 {
		t.Fatalf("scheduled %d units behind slow head, want concurrency window 3", got)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGitHubHistoryPolicyChangesInvalidateUnchangedSkip(t *testing.T) {
	base := Config{"include_commit_metadata": "false", "include_git_archives": "false"}
	policy := githubHistoryPolicy(base)
	r := githubRepoRef{PushedAt: "2026-07-01T00:00:00Z"}
	prev := githubRepoIncrementalState{Mode: githubScanModeHistory, PushedAt: r.PushedAt, RefHeads: map[string]string{"refs/heads/main": "abc"}, Policy: policy}
	if !githubRepoUnchanged(prev, r, policy) {
		t.Fatal("matching policy should permit unchanged skip")
	}
	changed := githubHistoryPolicy(Config{"include_commit_metadata": "true", "include_git_archives": "false"})
	if githubRepoUnchanged(prev, r, changed) {
		t.Fatal("policy change must force a history rescan")
	}
}

func TestRunGitHubSourceUnitsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runGitHubSourceUnits(ctx, []githubSourceUnit{{Surface: "repository-history", ID: "acme/repo"}}, 1,
		func(ctx context.Context, _ githubSourceUnit) githubUnitResult[struct{}] {
			return githubUnitResult[struct{}]{Err: ctx.Err()}
		},
		func(_ int, result githubUnitResult[struct{}]) error { return result.Err },
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}

func TestGitHubHistoryConcurrentReposIsolateFailureAndPersistNamespacedState(t *testing.T) {
	first, _ := buildFixtureRepo(t)
	second, _ := buildFixtureRepo(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"one": first, "two": second} {
		if err := os.Symlink(target, filepath.Join(root, "acme", name)); err != nil {
			t.Fatal(err)
		}
	}
	ref := func(name string) githubRepoRef {
		r := githubRepoRef{Name: name, Visibility: "private", Size: 1}
		r.Owner.Login = "acme"
		return r
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Fatalf("unexpected API path: %s", r.URL.Path)
		}
		writeJSON(t, w, []githubRepoRef{ref("two"), ref("missing"), ref("one")})
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token": "ghp_test", "org": "acme", "api_base": srv.URL,
		"repo_concurrency": "2", "clone_url_template": filepath.Join(root, "{owner}", "{repo}"),
	}
	seen := map[string]bool{}
	var mu sync.Mutex
	var flushed json.RawMessage
	flushFailure := errors.New("persist unavailable")
	ctx := context.WithValue(context.Background(), incrementalFlushCtxKey{}, sources.IncrementalFlushFunc(func(state json.RawMessage) error {
		flushed = append(flushed[:0], state...)
		return flushFailure
	}))
	err := scanGitHub(ctx, cfg, func(_ []byte, meta sources.Metadata) error {
		mu.Lock()
		defer mu.Unlock()
		if meta.GitHub != nil {
			seen[meta.GitHub.Repository] = true
		}
		return nil
	})
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("scanGitHub error = %v, want one structured source degradation", err)
	}
	if !errors.Is(err, flushFailure) {
		t.Fatalf("degradation must join final flush failure: %v", err)
	}
	if !seen["acme/one"] || !seen["acme/two"] {
		t.Fatalf("successful repositories not emitted after peer failure: %v", seen)
	}
	state, err := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if err != nil {
		t.Fatal(err)
	}
	history := state.Surfaces["repository-history"]
	if len(history) != 3 || history["acme/one"].Mode != githubScanModeHistory || history["acme/two"].Mode != githubScanModeHistory {
		t.Fatalf("namespaced history state = %#v", history)
	}
	if len(history["acme/missing"].RefHeads) != 0 {
		t.Fatal("failed repository must not gain completed ref-head state")
	}
	if len(flushed) == 0 || string(flushed) != cfg[configKeyIncrementalNextState] {
		t.Fatalf("final degraded state was not flushed deterministically: flush=%s next=%s", flushed, cfg[configKeyIncrementalNextState])
	}

	// Resume after the failed unit becomes available. Successful checkpoints
	// from the degraded run remain valid and the formerly failed unit joins the
	// same namespaced state without corrupting its peers.
	third, _ := buildFixtureRepo(t)
	if err := os.Symlink(third, filepath.Join(root, "acme", "missing")); err != nil {
		t.Fatal(err)
	}
	cfg[configKeyIncrementalPreviousState] = cfg[configKeyIncrementalNextState]
	delete(cfg, configKeyIncrementalNextState)
	if err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil }); err != nil {
		t.Fatalf("resume scan: %v", err)
	}
	resumed, err := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if err != nil {
		t.Fatal(err)
	}
	if got := len(resumed.Surfaces["repository-history"]); got != 3 {
		t.Fatalf("resumed state has %d repos, want 3", got)
	}
}

func BenchmarkRunGitHubSourceUnits(b *testing.B) {
	for _, concurrency := range []int{1, 4} {
		b.Run(fmt.Sprintf("concurrency-%d", concurrency), func(b *testing.B) {
			units := make([]githubSourceUnit, 16)
			for i := range units {
				units[i] = githubSourceUnit{Surface: "repository-history", ID: fmt.Sprintf("acme/repo-%d", i)}
			}
			b.ResetTimer()
			for range b.N {
				_, err := runGitHubSourceUnits(context.Background(), units, concurrency,
					func(context.Context, githubSourceUnit) githubUnitResult[struct{}] {
						time.Sleep(time.Millisecond)
						return githubUnitResult[struct{}]{}
					},
					func(int, githubUnitResult[struct{}]) error { return nil },
				)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
