package connectors

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

func TestGitHubHistoryRepoWalkTimeoutIsolatesUnitAndRetries(t *testing.T) {
	const (
		slowKey   = "acme/a-slow"
		peerKey   = "acme/b-peer"
		slowAdded = "slow-retry-content"
		peerAdded = "peer-completed-content"
	)

	slowRepo, _ := buildFixtureRepo(t)
	peerRepo, _ := buildFixtureRepo(t)
	cloneRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cloneRoot, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"a-slow": slowRepo, "b-peer": peerRepo} {
		if err := os.Symlink(target, filepath.Join(cloneRoot, "acme", name)); err != nil {
			t.Fatal(err)
		}
	}

	var pushedVersion atomic.Int32
	repoRef := func(name string) githubRepoRef {
		pushedAt := "2026-07-01T00:00:00Z"
		if pushedVersion.Load() > 0 {
			pushedAt = "2026-07-02T00:00:00Z"
		}
		r := githubRepoRef{Name: name, DefaultBranch: "feature", Visibility: "private", PushedAt: pushedAt, Size: 1}
		r.Owner.Login = "acme"
		return r
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Errorf("unexpected API path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, []githubRepoRef{repoRef("b-peer"), repoRef("a-slow")})
	}))
	t.Cleanup(srv.Close)

	cfg := Config{
		"token":              "ghp_test",
		"org":                "acme",
		"api_base":           srv.URL,
		"repo_concurrency":   "1",
		"clone_url_template": filepath.Join(cloneRoot, "{owner}", "{repo}"),
	}
	if err := scanGitHub(context.Background(), cfg, func([]byte, sources.Metadata) error { return nil }); err != nil {
		t.Fatalf("baseline scan: %v", err)
	}
	baselineRaw := cfg[configKeyIncrementalNextState]
	baseline, err := loadGitHubIncrementalState(baselineRaw)
	if err != nil {
		t.Fatal(err)
	}
	baselineSlow := baseline.Surfaces["repository-history"][slowKey]
	baselinePeer := baseline.Surfaces["repository-history"][peerKey]
	if len(baselineSlow.RefHeads) == 0 || len(baselinePeer.RefHeads) == 0 {
		t.Fatalf("baseline checkpoints missing: slow=%v peer=%v", baselineSlow.RefHeads, baselinePeer.RefHeads)
	}
	previousSlowHeads := maps.Clone(baselineSlow.RefHeads)

	appendGitHubTimeoutFixtureCommit(t, slowRepo, "slow-new.txt", slowAdded+"\n", time.Date(2026, 7, 2, 1, 0, 0, 0, time.UTC))
	appendGitHubTimeoutFixtureCommit(t, peerRepo, "peer-new.txt", peerAdded+"\n", time.Date(2026, 7, 2, 2, 0, 0, 0, time.UTC))
	pushedVersion.Store(1)
	cfg[configKeyIncrementalPreviousState] = baselineRaw
	delete(cfg, configKeyIncrementalNextState)
	cfg["repo_walk_timeout"] = "30s"

	githubRepoWalkTestHook = func(walkCtx context.Context, repoKey string) (context.Context, context.CancelFunc) {
		if repoKey != slowKey {
			return walkCtx, func() {}
		}
		return context.WithDeadline(walkCtx, time.Unix(0, 0))
	}
	t.Cleanup(func() { githubRepoWalkTestHook = nil })

	timedEmissions := map[string]string{}
	var timedMu sync.Mutex
	err = scanGitHub(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		if meta.GitHub == nil {
			return nil
		}
		timedMu.Lock()
		timedEmissions[meta.GitHub.Repository] += string(data)
		timedMu.Unlock()
		return nil
	})
	var degraded *engine.DegradedError
	if !errors.As(err, &degraded) || degraded.Total != 1 || degraded.Counts[engine.FailureSource] != 1 {
		t.Fatalf("timeout scan error = %v, want one structured source degradation", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), slowKey) {
		t.Fatalf("timeout identity or repository missing: %v", err)
	}
	if got := timedEmissions[peerKey]; !strings.Contains(got, peerAdded) {
		t.Fatalf("peer did not complete after timed-out repository: %q", got)
	}
	if got := timedEmissions[slowKey]; got != "" {
		t.Fatalf("timed-out repository emitted data: %q", got)
	}

	timedRaw := cfg[configKeyIncrementalNextState]
	timedState, err := loadGitHubIncrementalState(timedRaw)
	if err != nil {
		t.Fatal(err)
	}
	timedSlow := timedState.Surfaces["repository-history"][slowKey]
	timedPeer := timedState.Surfaces["repository-history"][peerKey]
	if !maps.Equal(timedSlow.RefHeads, previousSlowHeads) || timedSlow.PushedAt != baselineSlow.PushedAt {
		t.Fatalf("timed-out checkpoint advanced: before=%+v after=%+v", baselineSlow, timedSlow)
	}
	if maps.Equal(timedPeer.RefHeads, baselinePeer.RefHeads) || timedPeer.PushedAt == baselinePeer.PushedAt {
		t.Fatalf("peer checkpoint did not advance: before=%+v after=%+v", baselinePeer, timedPeer)
	}

	githubRepoWalkTestHook = nil
	cfg[configKeyIncrementalPreviousState] = timedRaw
	delete(cfg, configKeyIncrementalNextState)
	retryEmissions := map[string]string{}
	var retryMu sync.Mutex
	if err := scanGitHub(context.Background(), cfg, func(data []byte, meta sources.Metadata) error {
		if meta.GitHub == nil {
			return nil
		}
		retryMu.Lock()
		retryEmissions[meta.GitHub.Repository] += string(data)
		retryMu.Unlock()
		return nil
	}); err != nil {
		t.Fatalf("retry scan: %v", err)
	}
	if got := retryEmissions[slowKey]; !strings.Contains(got, slowAdded) {
		t.Fatalf("timed-out repository was not retried: %q", got)
	}
	if got := retryEmissions[peerKey]; got != "" {
		t.Fatalf("completed peer was unnecessarily rescanned: %q", got)
	}

	retriedState, err := loadGitHubIncrementalState(cfg[configKeyIncrementalNextState])
	if err != nil {
		t.Fatal(err)
	}
	retriedSlow := retriedState.Surfaces["repository-history"][slowKey]
	if maps.Equal(retriedSlow.RefHeads, previousSlowHeads) || retriedSlow.PushedAt != "2026-07-02T00:00:00Z" {
		t.Fatalf("retry did not advance timed-out checkpoint: %+v", retriedSlow)
	}
	if !maps.Equal(retriedState.Surfaces["repository-history"][peerKey].RefHeads, timedPeer.RefHeads) {
		t.Fatal("retry changed the completed peer checkpoint")
	}
}

func TestGitHubHistoryRepoWalkTimeoutStartsAfterOrderedTurn(t *testing.T) {
	const (
		slowKey = "acme/a-slow"
		peerKey = "acme/b-peer"
	)

	slowRepo, _ := buildFixtureRepo(t)
	peerRepo, _ := buildFixtureRepo(t)
	cloneRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cloneRoot, "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"a-slow": slowRepo, "b-peer": peerRepo} {
		if err := os.Symlink(target, filepath.Join(cloneRoot, "acme", name)); err != nil {
			t.Fatal(err)
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/orgs/acme/repos" {
			t.Errorf("unexpected API path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		writeJSON(t, w, []githubRepoRef{
			githubTimeoutRepoRef("b-peer"),
			githubTimeoutRepoRef("a-slow"),
		})
	}))
	t.Cleanup(srv.Close)

	peerCloned := make(chan struct{})
	var peerCloneOnce sync.Once
	githubCloneBytesObserver = func(repoKey string, _ int64) {
		if repoKey == peerKey {
			peerCloneOnce.Do(func() { close(peerCloned) })
		}
	}
	t.Cleanup(func() { githubCloneBytesObserver = nil })

	slowCancelReady := make(chan context.CancelFunc, 1)
	peerWalkStarted := make(chan struct{})
	var peerWalkOnce sync.Once
	githubRepoWalkTestHook = func(walkCtx context.Context, repoKey string) (context.Context, context.CancelFunc) {
		switch repoKey {
		case slowKey:
			ctx, cancel := context.WithCancel(walkCtx)
			slowCancelReady <- cancel
			return ctx, func() {}
		case peerKey:
			peerWalkOnce.Do(func() { close(peerWalkStarted) })
			return context.WithTimeout(walkCtx, 100*time.Millisecond)
		default:
			return walkCtx, func() {}
		}
	}
	t.Cleanup(func() { githubRepoWalkTestHook = nil })

	slowEmissionStarted := make(chan struct{})
	releaseSlowEmission := make(chan struct{})
	var slowEmissionOnce sync.Once
	emitted := make(map[string]int)
	var emittedMu sync.Mutex
	cfg := Config{
		"token":              "ghp_test",
		"org":                "acme",
		"api_base":           srv.URL,
		"repo_concurrency":   "2",
		"repo_walk_timeout":  "30s",
		"clone_url_template": filepath.Join(cloneRoot, "{owner}", "{repo}"),
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- scanGitHub(context.Background(), cfg, func(_ []byte, meta sources.Metadata) error {
			if meta.GitHub == nil {
				return nil
			}
			if meta.GitHub.Repository == slowKey {
				slowEmissionOnce.Do(func() { close(slowEmissionStarted) })
				<-releaseSlowEmission
			}
			emittedMu.Lock()
			emitted[meta.GitHub.Repository]++
			emittedMu.Unlock()
			return nil
		})
	}()

	select {
	case <-peerCloned:
	case <-time.After(10 * time.Second):
		t.Fatal("peer clone did not finish")
	}
	select {
	case <-slowEmissionStarted:
	case <-time.After(10 * time.Second):
		t.Fatal("slow repository did not reach ordered emission")
	}
	var cancelSlow context.CancelFunc
	select {
	case cancelSlow = <-slowCancelReady:
	case <-time.After(10 * time.Second):
		t.Fatal("slow repository walk did not start")
	}
	cancelSlow()

	select {
	case <-peerWalkStarted:
		t.Fatal("peer walk started before its ordered output turn")
	case <-time.After(200 * time.Millisecond):
	}
	close(releaseSlowEmission)

	select {
	case err := <-errCh:
		var degraded *engine.DegradedError
		if !errors.As(err, &degraded) || degraded.Total != 1 {
			t.Fatalf("scan error = %v, want one degraded repository", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan did not finish")
	}
	select {
	case <-peerWalkStarted:
	default:
		t.Fatal("peer walk never received its ordered output turn")
	}
	emittedMu.Lock()
	peerEmissions := emitted[peerKey]
	emittedMu.Unlock()
	if peerEmissions == 0 {
		t.Fatal("peer did not complete within its fresh walk timeout")
	}
}

func githubTimeoutRepoRef(name string) githubRepoRef {
	r := githubRepoRef{Name: name, DefaultBranch: "feature", Visibility: "private", PushedAt: "2026-07-01T00:00:00Z", Size: 1}
	r.Owner.Login = "acme"
	return r
}

func appendGitHubTimeoutFixtureCommit(t *testing.T, dir, path, data string, when time.Time) {
	t.Helper()
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		t.Fatal(err)
	}
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, path), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := worktree.Add(path); err != nil {
		t.Fatal(err)
	}
	signature := &object.Signature{Name: "timeout-test", Email: "timeout@example.com", When: when}
	if _, err := worktree.Commit("timeout fixture update", &gogit.CommitOptions{Author: signature, Committer: signature}); err != nil {
		t.Fatal(err)
	}
}
