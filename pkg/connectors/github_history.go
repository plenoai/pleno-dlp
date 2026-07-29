// GitHub full-history scan. Per repo: one bare git clone over smart HTTP, then
// a full-history walk of every ref via the git source (AllBranches=true). The
// git source owns the diff walk; this file only clones, bridges its Chunk
// channel into the connector Emit (rewriting GitMeta provenance into the
// GitHubMeta shape downstream formatters expect), and threads incremental
// state. See github.go's file header for the API-call accounting.
package connectors

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

// githubCloneBytesObserver is test/benchmark instrumentation. Production
// leaves it nil, avoiding an extra directory walk on every clone.
var githubCloneBytesObserver func(string, int64)

// githubRepoWalkTestHook runs after the per-repository deadline is installed
// and before history state can advance. It is nil outside tests.
var githubRepoWalkTestHook func(context.Context, string) (context.Context, context.CancelFunc)

func directoryBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if info, e := d.Info(); e == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

type githubSurfaceFailure struct {
	Surface string
	Err     error
}
type githubSurfaceFailures []githubSurfaceFailure

func (e githubSurfaceFailures) Error() string {
	return fmt.Sprintf("%d GitHub surface failure(s)", len(e))
}

// deriveCloneURL turns the REST api_base and an owner/repo into the smart-HTTP
// clone URL.
//
// Rules:
//   - Default public base "https://api.github.com" → host "github.com":
//     "https://github.com/<owner>/<repo>.git".
//   - GitHub Enterprise base ".../api/v3" → strip the "/api/v3" suffix and use
//     the remaining prefix as-is:
//     "https://ghe.example/api/v3" → "https://ghe.example/<owner>/<repo>.git".
//   - Any other base: strip a trailing "/api/v3" if present, else strip a
//     trailing "/" and append the path. (A bare host base like
//     "https://git.example" yields "https://git.example/<owner>/<repo>.git".)
//
// clone_url_template (advanced/test-only) overrides the derivation entirely:
// "{owner}" and "{repo}" placeholders are substituted. A template without a
// scheme is treated as a local filesystem path, which go-git's clone supports
// directly — this is how tests inject a fixture repo without a server.
func deriveCloneURL(apiBase, owner, repo, template string) (string, error) {
	if template != "" {
		u := strings.ReplaceAll(template, "{owner}", owner)
		u = strings.ReplaceAll(u, "{repo}", repo)
		return u, nil
	}
	if owner == "" || repo == "" {
		return "", fmt.Errorf("github: clone url needs owner and repo, got %q/%q", owner, repo)
	}
	base := strings.TrimRight(apiBase, "/")
	if base == strings.TrimRight(githubDefaultAPIBase, "/") {
		return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo), nil
	}
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("github: cannot derive clone url from api_base %q", apiBase)
	}
	// Strip the GHE REST suffix "/api/v3".
	u.Path = strings.TrimSuffix(u.Path, "/api/v3")
	u.Path = strings.TrimRight(u.Path, "/")
	u.Path = u.Path + "/" + owner + "/" + repo + ".git"
	return u.String(), nil
}

func validateGitHubAuthenticatedTransport(raw string, authenticated bool) error {
	if !authenticated {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return fmt.Errorf("github: invalid authenticated endpoint %q", raw)
	}
	if u.Scheme == "https" || (u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return nil
	}
	return fmt.Errorf("github: authenticated endpoint must use HTTPS (HTTP is allowed only for loopback tests): %q", raw)
}

func validateGitHubCloneTarget(apiBase, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("github: invalid clone target %q", raw)
	}
	base, err := url.Parse(apiBase)
	if err != nil || base.Host == "" {
		return fmt.Errorf("github: invalid api_base %q", apiBase)
	}
	if u.Scheme == "" {
		if !isLoopbackHost(base.Hostname()) {
			return errors.New("github: local clone templates are allowed only with a loopback API test endpoint")
		}
		return nil
	}
	if u.User != nil || canonicalOrigin(u) != canonicalOrigin(base) {
		return fmt.Errorf("github: untrusted clone template origin %q", u.Host)
	}
	return validateGitHubAuthenticatedTransport(raw, true)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func deriveWikiCloneURL(apiBase, owner, repo, template string) (string, error) {
	cloneURL, err := deriveCloneURL(apiBase, owner, repo, template)
	if err != nil {
		return "", err
	}
	if strings.HasSuffix(cloneURL, ".wiki.git") {
		return cloneURL, nil
	}
	if strings.HasSuffix(cloneURL, ".git") {
		return strings.TrimSuffix(cloneURL, ".git") + ".wiki.git", nil
	}
	return cloneURL + ".wiki.git", nil
}

type githubCloneFailureKind string

const (
	githubCloneMissing githubCloneFailureKind = "missing"
	githubCloneAuth    githubCloneFailureKind = "auth"
	githubCloneNetwork githubCloneFailureKind = "network"
)

type githubCloneError struct {
	Kind   githubCloneFailureKind
	Err    error
	Detail string
}

func (e *githubCloneError) Error() string {
	if e.Detail != "" {
		return "github clone " + string(e.Kind) + ": " + e.Detail
	}
	return "github clone " + string(e.Kind) + ": " + e.Err.Error()
}
func (e *githubCloneError) Unwrap() error { return e.Err }

func classifyGitHubCloneError(err error, detail string) error {
	text := strings.ToLower(detail + " " + err.Error())
	kind := githubCloneNetwork
	if strings.Contains(text, "repository not found") || strings.Contains(text, "does not exist") || strings.Contains(text, "not a git repository") {
		kind = githubCloneMissing
	} else if strings.Contains(text, "authentication failed") || strings.Contains(text, "authentication required") || strings.Contains(text, "unauthorized") || strings.Contains(text, "status code: 401") || strings.Contains(text, "status code: 403") {
		kind = githubCloneAuth
	}
	return &githubCloneError{Kind: kind, Err: err, Detail: strings.TrimSpace(detail)}
}

// scanGitHubHistory clones every enumerated repo and walks its full history.
// Per-repo failures (clone error, walk error) are tolerated so the org walk
// continues; context cancellation/deadline is terminal.
func scanGitHubHistory(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase, org, repo string, emit Emit) error {
	gitCfg, err := githubGitArtifactConfig(cfg)
	if err != nil {
		return err
	}
	mergeMode := "dense-resolution"
	if gitCfg.SkipMergeCommits {
		mergeMode = "off"
	}
	if gitCfg.TrufflehogCompatible {
		mergeMode = "off (trufflehog-compatible)"
	}
	fmt.Fprintf(os.Stderr, "github: history merge diff mode: %s\n", mergeMode)
	if _, err := githubRepoWalkTimeout(cfg); err != nil {
		return err
	}
	cli := newGitHubClient(apiBase, auth)
	repos, observedRepos, enumerationSkipped, err := githubEnumerateRepos(ctx, cli, cfg, org, repo)
	if err != nil {
		return err
	}
	// API ordering is not an incremental-state contract. Stable identity order
	// makes commits and partial flushes deterministic across pagination changes.
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].Owner.Login+"/"+repos[i].Name < repos[j].Owner.Login+"/"+repos[j].Name
	})
	previousState, err := loadGitHubIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	if previousState == nil {
		previousState = &githubIncrementalState{Version: 3, Surfaces: map[string]map[string]githubRepoIncrementalState{
			"repository-history": {},
			"repository-wiki":    {},
		}}
	}
	prunedState, err := prepareGitHubStateV3(previousState, observedRepos, cfg, time.Now())
	if err != nil {
		return err
	}
	previousRepos := previousState.Surfaces["repository-history"]
	previousWikis := previousState.Surfaces["repository-wiki"]
	// Scope filters must not erase checkpoints: a repository excluded for one
	// run can be re-included later without an avoidable full-history rescan.
	nextRepos := make(map[string]githubRepoIncrementalState, len(previousRepos))
	for key, state := range previousRepos {
		nextRepos[key] = state
	}
	nextWikis := make(map[string]githubRepoIncrementalState, len(previousWikis))
	for key, state := range previousWikis {
		nextWikis[key] = state
	}
	nextSurfaces := make(map[string]map[string]githubRepoIncrementalState, len(previousState.Surfaces))
	for surface, entries := range previousState.Surfaces {
		nextSurfaces[surface] = entries
	}
	nextSurfaces["repository-history"] = nextRepos
	nextSurfaces["repository-wiki"] = nextWikis
	nextState := &githubIncrementalState{Version: 3, ScopeFingerprint: previousState.ScopeFingerprint, CompleteRuns: previousState.CompleteRuns, Tombstones: previousState.Tombstones, Surfaces: nextSurfaces}
	concurrency, err := githubRepoConcurrency(cfg)
	if err != nil {
		return err
	}
	template := cfg["clone_url_template"]
	wikiTemplate := cfg["wiki_clone_url_template"]
	if template != "" {
		if err := validateGitHubCloneTarget(apiBase, template); err != nil {
			return err
		}
	}
	if wikiTemplate != "" {
		if err := validateGitHubCloneTarget(apiBase, wikiTemplate); err != nil {
			return err
		}
	}
	host := githubHostFromAPIBase(apiBase)
	commentsSince, err := githubCommentsSince(cfg, time.Now())
	if err != nil {
		return err
	}
	collaborationSince, err := githubCollaborationSince(cfg, time.Now())
	if err != nil {
		return err
	}
	orgStart := time.Now()
	historyPolicy := githubHistoryPolicy(cfg)
	var lastFlush time.Time
	var unitFailures []engine.ScanFailure
	unitFailureTotal := 0

	units := make([]githubSourceUnit, 0, len(repos)*2)
	reposByKey := make(map[string]githubRepoRef, len(repos))
	for _, r := range repos {
		repoKey := r.Owner.Login + "/" + r.Name
		units = append(units, githubSourceUnit{
			Surface: "repository-history",
			ID:      repoKey,
		})
		if parseBool(cfg["include_wikis"]) {
			units = append(units, githubSourceUnit{
				Surface: "repository-wiki", ID: repoKey,
			})
		}
		reposByKey[repoKey] = r
	}

	type repoOutcome struct {
		Next       githubRepoIncrementalState
		StateValid bool
	}
	unitOrder := make(map[string]int, len(units))
	for i, u := range units {
		unitOrder[u.Key()] = i
	}
	orderedEmit := newGitHubOrderedEmitter(ctx, len(units), emit)
	produce := func(ctx context.Context, unit githubSourceUnit) githubUnitResult[repoOutcome] {
		order := unitOrder[unit.Key()]
		walkControl := &githubOrderedWalkControl{emitter: orderedEmit, index: order}
		unitEmit := orderedEmit.EmitContext(ctx, order)
		r := reposByKey[unit.ID]
		repoKey := unit.ID
		if unit.Surface == "repository-wiki" {
			prevWiki := previousWikis[repoKey]
			if !r.HasWiki {
				return githubUnitResult[repoOutcome]{State: repoOutcome{Next: prevWiki, StateValid: prevWiki.Mode == githubScanModeHistory}, Stats: githubUnitStats{Skipped: "wiki-disabled"}}
			}
			seed := githubHistoryWalkSeed(prevWiki, historyPolicy)
			nextWiki, err := scanGitHubWikiHistory(ctx, cfg, auth, apiBase, host, wikiTemplate, r, seed, walkControl, unitEmit)
			if err != nil {
				if isMissingWikiError(err) {
					return githubUnitResult[repoOutcome]{State: repoOutcome{Next: prevWiki, StateValid: prevWiki.Mode == githubScanModeHistory}, Stats: githubUnitStats{Skipped: "wiki-missing"}}
				}
				return githubUnitResult[repoOutcome]{State: repoOutcome{Next: prevWiki, StateValid: prevWiki.Mode == githubScanModeHistory}, Err: err}
			}
			nextWiki.StableID = githubStableRepoID(r, repoKey)
			nextWiki.LastSeen = time.Now().UTC().Format(time.RFC3339)
			return githubUnitResult[repoOutcome]{State: repoOutcome{Next: nextWiki, StateValid: true}, Stats: githubUnitStats{CostItems: 1}}
		}
		sizeNote := ""
		if r.Size > 0 {
			sizeNote = " (" + formatBytes(uint64(r.Size)*1024) + ")"
		}
		fmt.Fprintf(os.Stderr, "github: scan %s%s\n", repoKey, sizeNote)
		repoStart := time.Now()
		prevRepo := previousRepos[repoKey]
		var nextRepo githubRepoIncrementalState
		var surfaceFailures githubSurfaceFailures
		empty := false
		unchanged := githubRepoUnchanged(prevRepo, r, historyPolicy)
		if unchanged {
			// No push since the walk that produced prevRepo.RefHeads: cloning
			// would fetch the same refs and the seeded walk would emit nothing.
			// Carry the state; only Visibility can have moved without a push
			// (comments can too — their scan below still runs on this path).
			nextRepo = prevRepo
			nextRepo.Visibility = githubVisibility(r)
			fmt.Fprintf(os.Stderr, "github: scan %s unchanged since last run (pushed_at %s), clone skipped\n", repoKey, r.PushedAt)
		} else {
			var err error
			seed := githubHistoryWalkSeed(prevRepo, historyPolicy)
			nextRepo, err = scanGitHubRepoHistory(ctx, cfg, auth, apiBase, host, template, r, seed, walkControl, unitEmit)
			if err != nil {
				if ctx.Err() != nil {
					return githubUnitResult[repoOutcome]{Err: ctx.Err()}
				}
				nextRepo = prevRepo
				if errors.Is(err, gitsource.ErrNoBranchHeads) {
					empty = true
					nextRepo.Mode = githubScanModeHistory
					nextRepo.Policy = historyPolicy
					nextRepo.PushedAt = r.PushedAt
					nextRepo.Visibility = githubVisibility(r)
					nextRepo.RefHeads = nil
					fmt.Fprintf(os.Stderr, "github: scan %s has no branch heads, history skipped\n", repoKey)
				} else {
					fmt.Fprintf(os.Stderr, "WARN: github: scan failed for %s after %s, skipping: %v\n", repoKey, time.Since(repoStart).Round(time.Second), err)
					surfaceFailures = append(surfaceFailures, githubSurfaceFailure{Surface: "repository-history", Err: err})
				}
			}
		}
		seedGitHubCollaborationState(&nextRepo, prevRepo)
		if parseBool(cfg["include_comments"]) {
			// Comments are REST-based. To keep comment incrementality, carry the
			// previous comment cursors only when the previous state was history
			// mode; legacy tree-mode state never carried history comment cursors,
			// so loading it triggers a one-time full comment rescan.
			commentPrev := githubRepoIncrementalState{}
			hasCommentPrev := false
			if prevRepo.Mode == githubScanModeHistory {
				commentPrev = prevRepo
				hasCommentPrev = true
			}
			if err := scanGitHubCommentsIncremental(ctx, cli, r, commentPrev, hasCommentPrev, &nextRepo, commentsSince, unitEmit); err != nil {
				if ctx.Err() != nil {
					return githubUnitResult[repoOutcome]{Err: ctx.Err()}
				}
				// Code walked to the new heads but comments didn't finish:
				// keep the new RefHeads and the previous comment cursors so
				// neither side full-rescans next run. A partially emitted
				// comment page may re-emit then; dedup downstream absorbs it.
				fmt.Fprintf(os.Stderr, "WARN: github: comment scan failed for %s, skipping: %v\n", repoKey, err)
				merged := nextRepo
				merged.IssueComments = commentPrev.IssueComments
				merged.PullReviewComments = commentPrev.PullReviewComments
				nextRepo = merged
				surfaceFailures = append(surfaceFailures, githubSurfaceFailure{Surface: "repository-comments", Err: err})
			}
		}
		collabPrev := githubRepoIncrementalState{}
		if prevRepo.Mode == githubScanModeHistory {
			collabPrev = prevRepo
		}
		if parseBool(cfg["include_issues"]) {
			if err := scanGitHubIssuesIncremental(ctx, cli, r, collabPrev, &nextRepo, collaborationSince, unitEmit); err != nil {
				if ctx.Err() != nil {
					return githubUnitResult[repoOutcome]{Err: ctx.Err()}
				}
				nextRepo.Issues = collabPrev.Issues
				surfaceFailures = append(surfaceFailures, githubSurfaceFailure{Surface: "repository-issues", Err: err})
			}
		}
		if parseBool(cfg["include_pull_requests"]) {
			if err := scanGitHubPullRequestsIncremental(ctx, cli, r, collabPrev, &nextRepo, collaborationSince, unitEmit); err != nil {
				if ctx.Err() != nil {
					return githubUnitResult[repoOutcome]{Err: ctx.Err()}
				}
				nextRepo.PullRequests = collabPrev.PullRequests
				surfaceFailures = append(surfaceFailures, githubSurfaceFailure{Surface: "repository-pull-requests", Err: err})
			}
		}
		fmt.Fprintf(os.Stderr, "github: scan %s done in %s\n", repoKey, time.Since(repoStart).Round(time.Second))
		stats := githubUnitStats{CostItems: 1}
		if empty {
			stats.Skipped = "empty"
		} else if unchanged {
			stats.Skipped = "unchanged"
		} else if r.Size > 0 {
			// GitHub reports repository size in KiB. This is an estimate of
			// source work, not exact wire bytes after partial-clone filtering.
			stats.CostBytes = r.Size * 1024
		}
		var surfaceErr error
		if len(surfaceFailures) > 0 {
			surfaceErr = surfaceFailures
		}
		nextRepo.StableID = githubStableRepoID(r, repoKey)
		nextRepo.LastSeen = time.Now().UTC().Format(time.RFC3339)
		nextRepo.UnobservedRuns = 0
		nextRepo.UnobservedSince = ""
		return githubUnitResult[repoOutcome]{State: repoOutcome{Next: nextRepo, StateValid: true}, Stats: stats, Err: surfaceErr}
	}

	commit := func(_ int, result githubUnitResult[repoOutcome]) error {
		if err := orderedEmit.Close(unitOrder[result.Unit.Key()]); err != nil {
			return err
		}
		if result.Err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if result.State.StateValid {
			if result.Unit.Surface == "repository-wiki" {
				nextWikis[result.Unit.ID] = result.State.Next
			} else {
				nextRepos[result.Unit.ID] = result.State.Next
			}
		}
		if result.Err != nil {
			if failures, ok := result.Err.(githubSurfaceFailures); ok {
				for _, failure := range failures {
					unitFailureTotal++
					if len(unitFailures) < 32 {
						unitFailures = append(unitFailures, engine.ScanFailure{Kind: engine.FailureSource, Source: failure.Surface + ":" + result.Unit.ID, Err: failure.Err})
					}
				}
			} else {
				unitFailureTotal++
				if len(unitFailures) < 32 {
					unitFailures = append(unitFailures, engine.ScanFailure{Kind: engine.FailureSource, Source: result.Unit.Key(), Err: result.Err})
				}
			}
		}
		// per-repo flush。 cmd 層が「ここまで進んだ」状態を atomic に persist
		// するので、 scan が途中の repo で死んでも次回 run が resume できる。
		// nextState は org 全体を丸ごと marshal するため repo 数に対して
		// O(N^2) のアロケーションになる。 毎 repo ではなく時間で間引き、
		// クラッシュ時のロスを interval 分に抑えつつ GC 圧力を repo 数から
		// 切り離す。 flush err は次の flush か final marshal で recover
		// できるので WARN だけ。
		if flush := IncrementalFlushFromContext(ctx); flush != nil && time.Since(lastFlush) >= githubIncrementalFlushInterval {
			if data, err := json.Marshal(nextState); err == nil {
				if ferr := flush(data); ferr != nil {
					fmt.Fprintf(os.Stderr, "WARN: github incremental flush failed after %s: %v\n", result.Unit.ID, ferr)
				}
				lastFlush = time.Now()
			}
		}
		return nil
	}

	stats, err := runGitHubSourceUnits(ctx, units, concurrency, produce, commit)
	if err != nil {
		return err
	}
	if err := orderedEmit.Wait(); err != nil {
		return err
	}
	var finalFlushErr error
	if data, err := json.Marshal(nextState); err == nil {
		cfg[configKeyIncrementalNextState] = string(data)
		if flush := IncrementalFlushFromContext(ctx); flush != nil {
			if ferr := flush(data); ferr != nil {
				finalFlushErr = fmt.Errorf("github: final incremental flush: %w", ferr)
			}
		}
	} else {
		finalFlushErr = fmt.Errorf("github: marshal final incremental state: %w", err)
	}
	fmt.Fprintf(os.Stderr, "github: org scan complete: %d units, concurrency %d, %d unchanged, %d empty, wiki-disabled=%d wiki-missing=%d, %d filtered (fork=%d archived=%d excluded=%d not-included=%d duplicate=%d), %d failed, %d items, %d bytes, peak %d pending, took %s\n",
		stats.Total, concurrency, stats.Skipped["unchanged"], stats.Skipped["empty"],
		stats.Skipped["wiki-disabled"], stats.Skipped["wiki-missing"],
		enumerationSkipped["fork"]+enumerationSkipped["archived"]+enumerationSkipped["excluded"]+enumerationSkipped["not-included"]+enumerationSkipped["duplicate"],
		enumerationSkipped["fork"], enumerationSkipped["archived"], enumerationSkipped["excluded"], enumerationSkipped["not-included"], enumerationSkipped["duplicate"],
		stats.Failed, stats.CostItems, stats.CostBytes, stats.PeakInFlight, time.Since(orgStart).Round(time.Second))
	if prunedState > 0 {
		fmt.Fprintf(os.Stderr, "github: incremental state pruned=%d\n", prunedState)
	}
	rateWait, constrainedAcquisitions := cli.rateCoordinationStats()
	fmt.Fprintf(os.Stderr, "github: rate coordination: %d constrained request acquisition(s), %s aggregate permit wait\n", constrainedAcquisitions, rateWait.Round(time.Millisecond))
	if unitFailureTotal > 0 {
		degraded := &engine.DegradedError{
			Total:    unitFailureTotal,
			Counts:   map[engine.FailureKind]int{engine.FailureSource: unitFailureTotal},
			Failures: unitFailures,
		}
		return errors.Join(degraded, finalFlushErr)
	}
	return finalFlushErr
}

func githubHistoryWalkSeed(prev githubRepoIncrementalState, policy string) githubRepoIncrementalState {
	if prev.Policy != policy {
		return githubRepoIncrementalState{}
	}
	return prev
}

// githubRepoUnchanged reports whether the repo received no push since the
// previous history walk, so the clone+walk can be skipped and prev carried
// forward. It demands history-mode state with RefHeads (legacy tree-mode state
// must take the one-time full rescan) and a non-empty pushed_at on both sides:
// the enumeration reports pushed_at as null for never-pushed repos, and state
// written by builds predating PushedAt carries none — neither proves anything.
func githubRepoUnchanged(prev githubRepoIncrementalState, r githubRepoRef, policy string) bool {
	return prev.Mode == githubScanModeHistory &&
		len(prev.RefHeads) > 0 &&
		prev.PushedAt != "" &&
		prev.PushedAt == r.PushedAt &&
		prev.Policy == policy
}

func seedGitHubCollaborationState(next *githubRepoIncrementalState, prev githubRepoIncrementalState) {
	if next.IssueComments == nil {
		next.IssueComments = make(map[string]githubCommentIncrementalState, len(prev.IssueComments))
		for key, state := range prev.IssueComments {
			next.IssueComments[key] = state
		}
	}
	if next.PullReviewComments == nil {
		next.PullReviewComments = make(map[string]githubCommentIncrementalState, len(prev.PullReviewComments))
		for key, state := range prev.PullReviewComments {
			next.PullReviewComments[key] = state
		}
	}
	if next.Issues == nil {
		next.Issues = make(map[string]githubEntityIncrementalState, len(prev.Issues))
		for key, state := range prev.Issues {
			next.Issues[key] = state
		}
	}
	if next.PullRequests == nil {
		next.PullRequests = make(map[string]githubEntityIncrementalState, len(prev.PullRequests))
		for key, state := range prev.PullRequests {
			next.PullRequests[key] = state
		}
	}
}

// scanGitHubRepoHistory clones one repo bare and walks it. It returns the
// repo's next incremental state (RefHeads after the walk).
func scanGitHubRepoHistory(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase, host, template string, repo githubRepoRef, prev githubRepoIncrementalState, walkControl *githubOrderedWalkControl, emit Emit) (githubRepoIncrementalState, error) {
	cloneURL, err := deriveCloneURL(apiBase, repo.Owner.Login, repo.Name, template)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	return scanGitHubGitHistory(ctx, cfg, auth, host, cloneURL, repo, prev, false, walkControl, emit)
}

func scanGitHubWikiHistory(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase, host, template string, repo githubRepoRef, prev githubRepoIncrementalState, walkControl *githubOrderedWalkControl, emit Emit) (githubRepoIncrementalState, error) {
	cloneURL, err := deriveWikiCloneURL(apiBase, repo.Owner.Login, repo.Name, template)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	if u, parseErr := url.Parse(cloneURL); parseErr == nil && u.Scheme == "" {
		if _, statErr := os.Stat(cloneURL); statErr != nil && os.IsNotExist(statErr) {
			return githubRepoIncrementalState{}, &githubCloneError{Kind: githubCloneMissing, Err: statErr, Detail: "wiki repository not found"}
		}
	}
	return scanGitHubGitHistory(ctx, cfg, auth, host, cloneURL, repo, prev, true, walkControl, emit)
}

func scanGitHubGitHistory(ctx context.Context, cfg Config, auth githubTokenProvider, host, cloneURL string, repo githubRepoRef, prev githubRepoIncrementalState, wiki bool, walkControl *githubOrderedWalkControl, emit Emit) (githubRepoIncrementalState, error) {
	walkTimeout, err := githubRepoWalkTimeout(cfg)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}

	dir, err := os.MkdirTemp("", "pleno-gh-clone-")
	if err != nil {
		return githubRepoIncrementalState{}, fmt.Errorf("github: mktemp for clone: %w", err)
	}
	defer os.RemoveAll(dir)

	repoKey := repo.Owner.Login + "/" + repo.Name
	if wiki {
		repoKey += ".wiki"
	}
	hb := startRepoHeartbeat(repoKey, githubHeartbeatInterval)
	defer hb.end()

	token, err := githubCloneToken(ctx, auth, cloneURL)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}

	cloneStart := time.Now()
	progress := &cloneProgressWriter{repoKey: repoKey, interval: githubHeartbeatInterval}
	usedNative, err := cloneRepoBare(ctx, cloneURL, dir, token, progress)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return githubRepoIncrementalState{}, err
		}
		return githubRepoIncrementalState{}, fmt.Errorf("github: clone %s/%s: %w", repo.Owner.Login, repo.Name, err)
	}
	fmt.Fprintf(os.Stderr, "github: clone %s done in %s (%s)\n", repoKey, time.Since(cloneStart).Round(time.Second), cloneMethodLabel(usedNative))
	if githubCloneBytesObserver != nil {
		githubCloneBytesObserver(repoKey, directoryBytes(dir))
	}
	if walkControl != nil {
		hb.setPhase("ordered-wait")
		if err := walkControl.emitter.WaitTurn(ctx, walkControl.index); err != nil {
			return githubRepoIncrementalState{}, err
		}
	}
	hb.setPhase("walk")
	walkStart := time.Now()
	walkCtx := ctx
	cancelWalk := func() {}
	if walkTimeout > 0 {
		walkCtx, cancelWalk = context.WithTimeout(ctx, walkTimeout)
	}
	defer cancelWalk()
	if hook := githubRepoWalkTestHook; hook != nil {
		var cancelHook context.CancelFunc
		walkCtx, cancelHook = hook(walkCtx, repoKey)
		defer cancelHook()
	}
	walkEmit := emit
	if walkControl != nil {
		walkEmit = walkControl.emitContext(walkCtx)
	}

	// Open the bare clone once and reuse the handle for the ref-head read
	// below. This file previously reopened the clone via gogit.PlainOpen a
	// second time inside gitRefHeads purely to list refs; each open attaches
	// go-git's 96 MiB object LRU cache, so the reopen doubled that cost for
	// no benefit once we already have a working directory. The git source's
	// own PlainOpen (pkg/sources/git/git.go, out of this file's scope) still
	// opens the clone independently for the walk — that duplication cannot be
	// removed from this side of the package boundary.
	gitRepo, err := gogit.PlainOpen(dir)
	if err != nil {
		return githubRepoIncrementalState{}, fmt.Errorf("github: open clone %s/%s: %w", repo.Owner.Login, repo.Name, err)
	}

	visibility := githubVisibility(repo)
	src := &gitsource.Source{}
	gitCfg, err := githubGitArtifactConfig(cfg)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	gitCfg.Repo, gitCfg.AllBranches = dir, true
	raw, err := json.Marshal(gitCfg)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	// The git source's verify flag only stamps chunk.Verify, which we discard
	// when re-emitting via the connector Emit (the engine sets verify on the
	// connector path). false is correct here.
	if err := src.Init(walkCtx, "github", 0, 0, false, raw, 1); err != nil {
		return githubRepoIncrementalState{}, fmt.Errorf("github: init git walk for %s/%s: %w", repo.Owner.Login, repo.Name, err)
	}
	// Seed the git walk's stop-set from the previous run's ref heads.
	// Legacy tree-mode state is ignored (Mode guard) → one full scan.
	if prev.Mode == githubScanModeHistory && len(prev.RefHeads) > 0 {
		if seed := gitIncrementalSeed(prev.RefHeads); seed != nil {
			if err := src.SetIncrementalState(seed); err != nil {
				return githubRepoIncrementalState{}, fmt.Errorf("github: seed incremental walk: %w", err)
			}
		}
	}

	// Bridge the git source's Chunk channel into the connector Emit, rewriting
	// GitMeta → GitHubMeta. The walk runs in a goroutine; we drain on this one.
	// Buffer kept small (not unbuffered, not the old 64): full-history chunks
	// carry up to maxBlobSize (50 MiB) of file content each (issue #264), so a
	// deep buffer bounds nothing — 64 slots could hold ~3.2 GiB in flight
	// between this goroutine and the engine's consumer. 4 slots is enough to
	// keep producer and consumer from lock-stepping on every chunk while
	// capping in-flight bytes at a couple hundred MiB worst case. The mid-term
	// fix (emit diff hunks instead of full files, tracked in #264) is out of
	// scope here.
	ch := make(chan *sources.Chunk, 4)
	walkErr := make(chan error, 1)
	go func() {
		walkErr <- src.Chunks(walkCtx, ch)
		close(ch)
	}()

	link := func(commit, path string, line int) string {
		if wiki {
			return githubWikiLink(host, repo.Owner.Login, repo.Name, commit, path, line)
		}
		if strings.HasPrefix(path, "commit:") {
			return "https://" + host + "/" + repo.Owner.Login + "/" + repo.Name + "/commit/" + commit
		}
		return githubBlobLink(host, repo.Owner.Login, repo.Name, commit, path, line)
	}
	var emitErr error
	for c := range ch {
		hb.addChunk()
		if emitErr != nil {
			continue // drain to let the producer finish; report first error
		}
		gm := c.SourceMetadata.Git
		if gm == nil {
			continue
		}
		meta := sources.Metadata{
			GitHub: &sources.GitHubMeta{
				Repository: repo.Owner.Login + "/" + repo.Name,
				Owner:      repo.Owner.Login,
				Repo:       repo.Name,
				Commit:     gm.Commit,
				File:       gm.File,
				Path:       gm.File,
				Line:       gm.Line,
				Visibility: visibility,
				Link:       link(gm.Commit, gm.File, gm.Line),
			},
		}
		if wiki {
			meta.GitHub.Entity = "wiki"
			meta.GitHub.Part = "page"
		}
		if err := walkEmit(c.Data, meta); err != nil {
			emitErr = err
		}
	}
	if err := <-walkErr; err != nil {
		return githubRepoIncrementalState{}, normalizeGitHubRepoWalkError(ctx, repoKey, walkTimeout, err)
	}
	if emitErr != nil {
		return githubRepoIncrementalState{}, emitErr
	}
	if err := walkCtx.Err(); err != nil {
		return githubRepoIncrementalState{}, normalizeGitHubRepoWalkError(ctx, repoKey, walkTimeout, err)
	}
	fmt.Fprintf(os.Stderr, "github: walk %s done: %d chunks in %s\n", repoKey, hb.chunks.Load(), time.Since(walkStart).Round(time.Second))

	next := githubRepoIncrementalState{
		Mode:       githubScanModeHistory,
		Visibility: visibility,
		PushedAt:   repo.PushedAt,
		Policy:     githubHistoryPolicy(cfg),
	}
	if wiki {
		next.PushedAt = ""
	}
	heads, err := gitRefHeads(gitRepo)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	next.RefHeads = heads
	return next, nil
}

func normalizeGitHubRepoWalkError(parent context.Context, repoKey string, timeout time.Duration, err error) error {
	if errors.Is(err, context.DeadlineExceeded) && parent.Err() == nil && timeout > 0 {
		return fmt.Errorf("github: repository walk %s exceeded %s: %w", repoKey, timeout, err)
	}
	return err
}

func githubWikiLink(host, owner, repo, commit, path string, line int) string {
	outer := strings.SplitN(path, "!", 2)[0]
	if strings.HasPrefix(outer, "commit:") {
		return "https://" + host + "/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + ".wiki/commit/" + url.PathEscape(commit)
	}
	ext := strings.ToLower(filepath.Ext(outer))
	base := strings.TrimSuffix(filepath.Base(outer), filepath.Ext(outer))
	if (ext == ".md" || ext == ".markdown") && base != "_Sidebar" && base != "_Footer" && !strings.Contains(path, "!") {
		page := strings.TrimSuffix(strings.TrimSuffix(outer, ".md"), ".markdown")
		segments := strings.Split(filepath.ToSlash(page), "/")
		for i := range segments {
			segments[i] = url.PathEscape(segments[i])
		}
		return "https://" + host + "/" + url.PathEscape(owner) + "/" + url.PathEscape(repo) + "/wiki/" + strings.Join(segments, "/")
	}
	return githubBlobLink(host, owner, repo+".wiki", commit, outer, line)
}

func isMissingWikiError(err error) bool {
	var cloneErr *githubCloneError
	return errors.As(err, &cloneErr) && cloneErr.Kind == githubCloneMissing
}

func githubGitArtifactConfig(cfg Config) (gitsource.Config, error) {
	parseI64 := func(key string, def int64) (int64, error) {
		raw := cfg[key]
		if raw == "" {
			return def, nil
		}
		n, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || n <= 0 {
			return 0, fmt.Errorf("github: %s must be a positive integer, got %q", key, raw)
		}
		return n, nil
	}
	parseI := func(key string, def int) (int, error) { n, e := parseI64(key, int64(def)); return int(n), e }
	blob, e := parseI64("git_artifact_max_bytes", 10<<20)
	if e != nil {
		return gitsource.Config{}, e
	}
	expanded, e := parseI64("archive_max_expanded_bytes", 50<<20)
	if e != nil {
		return gitsource.Config{}, e
	}
	files, e := parseI("archive_max_files", 1000)
	if e != nil {
		return gitsource.Config{}, e
	}
	depth, e := parseI("archive_max_depth", 3)
	if e != nil {
		return gitsource.Config{}, e
	}
	timeout := 5 * time.Second
	if raw := cfg["archive_timeout"]; raw != "" {
		timeout, e = time.ParseDuration(raw)
		if e != nil || timeout <= 0 {
			return gitsource.Config{}, fmt.Errorf("github: archive_timeout must be a positive duration, got %q", raw)
		}
	}
	if blob > 50<<20 || expanded > 200<<20 || files > 10000 || depth > 8 || timeout > time.Minute {
		return gitsource.Config{}, errors.New("github: artifact limits exceed hard caps")
	}
	return gitsource.Config{IncludeCommitMetadata: parseBool(cfg["include_commit_metadata"]), SkipMergeCommits: parseBool(cfg["skip_merge_commits"]), TrufflehogCompatible: parseBool(cfg["trufflehog_compatible"]), IncludeGitArchives: parseBool(cfg["include_git_archives"]), IncludeGitBinaries: parseBool(cfg["include_git_binaries"]), GitArtifactMaxBytes: blob, ArchiveMaxExpandedBytes: expanded, ArchiveMaxFiles: files, ArchiveMaxDepth: depth, ArchiveTimeout: timeout}, nil
}

func githubRepoWalkTimeout(cfg Config) (time.Duration, error) {
	raw := strings.TrimSpace(cfg["repo_walk_timeout"])
	if raw == "" || raw == "0" || raw == "0s" {
		return 0, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil || timeout <= 0 {
		return 0, fmt.Errorf("github: repo_walk_timeout must be a positive duration or 0, got %q", raw)
	}
	return timeout, nil
}

// githubCloneToken fetches the auth token once per clone, shared by both the
// native-git and go-git clone paths below. A local-path clone URL (no
// scheme/host, as tests use to inject a fixture repo) needs no auth.
func githubCloneToken(ctx context.Context, auth githubTokenProvider, cloneURL string) (string, error) {
	if u, err := url.Parse(cloneURL); err != nil || u.Scheme == "" || u.Host == "" {
		return "", nil
	}
	if auth == nil {
		return "", nil
	}
	return auth.Token(ctx)
}

// cloneRepoBare clones cloneURL into dir as a bare repo, preferring an exec
// of the native git binary over go-git's in-process client (issue #265).
//
// Native git resolves the packfile — negotiation, delta resolution, idx
// construction — inside the git subprocess, so a multi-GB history costs that
// subprocess's memory, not this process's. go-git's PlainCloneContext
// materializes delta resolution in-process instead, which is the memory
// scaling problem #265 reports. The native clone intentionally remains
// complete: a filtered clone needs authenticated demand-fetches during
// `git log --patch`, but clone credentials are ephemeral and the history
// walk disables lazy fetching so it cannot unexpectedly access the network.
//
// go-git remains the fallback for environments without a `git` binary on
// PATH (e.g. a from-scratch pure-Go build/container) so those keep working,
// just without the memory or filter improvement. Returns which path ran.
func cloneRepoBare(ctx context.Context, cloneURL, dir, token string, progress io.Writer) (usedNative bool, err error) {
	gitBin, lookErr := exec.LookPath("git")
	if lookErr != nil {
		return false, cloneWithGoGit(ctx, cloneURL, dir, token, progress)
	}
	return true, cloneWithNativeGit(ctx, gitBin, cloneURL, dir, token, progress)
}

// cloneMethodLabel renders cloneRepoBare's choice for the done-clone log line.
func cloneMethodLabel(usedNative bool) string {
	if usedNative {
		return "native git"
	}
	return "go-git fallback: git binary not found on PATH"
}

// cloneWithGoGit is the pure-Go fallback clone path. token, if non-empty, is
// passed as a struct field (githttp.BasicAuth), never URL-embedded, so it
// cannot leak into a URL string anywhere on this path.
func cloneWithGoGit(ctx context.Context, cloneURL, dir, token string, progress io.Writer) error {
	// Mirror is required for refs/notes/*; a normal bare clone fetches branch
	// heads and tags but can silently omit commit notes from #322's surface.
	cloneOpts := &gogit.CloneOptions{URL: cloneURL, Progress: progress, Mirror: true}
	if token != "" {
		if u, err := url.Parse(cloneURL); err == nil && u.Scheme != "" && u.Host != "" {
			cloneOpts.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
		}
	}
	_, err := gogit.PlainCloneContext(ctx, dir, true, cloneOpts)
	if err != nil {
		return classifyGitHubCloneError(err, "")
	}
	return nil
}

// cloneWithNativeGit execs `git clone --mirror`.
//
// The token never touches argv: it is handed to git as an Authorization
// header through GIT_CONFIG_* environment variables (nativeGitAuthEnv, the
// same mechanism actions/checkout uses), because argv is world-readable via
// process listings while a child's environment is owner-readable only.
// redactCloneError additionally scrubs the token from any returned error as
// defense-in-depth, though git's own fatal/remote messages already omit
// credentials.
func cloneWithNativeGit(ctx context.Context, gitBin, cloneURL, dir, token string, progress io.Writer) error {
	cmd := exec.CommandContext(ctx, gitBin, nativeGitCloneArgs(cloneURL, dir)...)
	var diagnostic bytes.Buffer
	cmd.Stderr = io.MultiWriter(progress, &diagnostic)
	// Never prompt interactively: a hung terminal prompt on a bad/expired
	// token would look identical to a stalled clone from the heartbeat's
	// point of view. Fail fast instead.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cmd.Env = append(cmd.Env, nativeGitAuthEnv(cloneURL, token)...)
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		classified := classifyGitHubCloneError(redactCloneError(err, token), diagnostic.String())
		if cloneErr, ok := classified.(*githubCloneError); ok {
			cloneErr.Detail = redactCloneDiagnostic(cloneErr.Detail, token)
		}
		return classified
	}
	return nil
}

func redactCloneDiagnostic(detail, token string) string {
	if len(token) < 8 {
		return detail
	}
	return strings.ReplaceAll(detail, token, "[REDACTED]")
}

// nativeGitCloneArgs builds the argv for the native mirror clone. Split out
// from cloneWithNativeGit so the exact flags and ordering can be asserted in
// a unit test without executing git.
func nativeGitCloneArgs(cloneURL, dir string) []string {
	return []string{
		"clone",
		"--mirror",
		"--progress",
		"--",
		cloneURL,
		dir,
	}
}

// nativeGitAuthEnv returns the GIT_CONFIG_* environment entries that hand
// the token to native git as an Authorization header — never via argv or the
// clone URL, so it cannot appear in process listings. Empty when there is no
// token or the URL is a local path (no scheme/host — the shape tests use to
// inject a fixture repo, which needs no auth). The Basic credentials mirror
// the x-access-token convention the go-git path uses via BasicAuth.
func nativeGitAuthEnv(cloneURL, token string) []string {
	if token == "" {
		return nil
	}
	u, err := url.Parse(cloneURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=Authorization: Basic " + basic,
	}
}

// redactCloneError scrubs the raw token out of a native-clone error before
// it can propagate into logs or returned errors. Belt-and-suspenders on top
// of the token never being in argv (see nativeGitAuthEnv) and git's own
// credential-free fatal messages.
func redactCloneError(err error, token string) error {
	if len(token) < 8 {
		return err
	}
	redacted := strings.ReplaceAll(err.Error(), token, "REDACTED")
	basic := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	redacted = strings.ReplaceAll(redacted, basic, "REDACTED")
	return errors.New(redacted)
}

// gitRefHeads reads the ref → sha map (branches and remotes) from an already
// -open clone handle, so the next run can stop the walk at these heads. The
// caller opens the clone once (gogit.PlainOpen) and passes the handle here;
// this used to reopen the clone itself, doubling go-git's 96 MiB object LRU
// cache for no reason (see the comment where this is called from).
func gitRefHeads(repo *gogit.Repository) (map[string]string, error) {
	refs, err := repo.References()
	if err != nil {
		return nil, fmt.Errorf("github: list clone refs: %w", err)
	}
	defer refs.Close()
	out := map[string]string{}
	err = refs.ForEach(func(ref *plumbing.Reference) error {
		if ref.Type() != plumbing.HashReference {
			return nil
		}
		name := ref.Name().String()
		if !strings.HasPrefix(name, "refs/heads/") && !strings.HasPrefix(name, "refs/remotes/") {
			return nil
		}
		out[name] = ref.Hash().String()
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// gitIncrementalSeed builds the git source's incremental-state JSON from a
// ref→sha map. The shape mirrors pkg/sources/git's incrementalState
// (version/head/heads); heads is the stop-set the walk will not descend past.
func gitIncrementalSeed(refHeads map[string]string) json.RawMessage {
	heads := make([]string, 0, len(refHeads))
	for _, sha := range refHeads {
		if sha != "" {
			heads = append(heads, sha)
		}
	}
	if len(heads) == 0 {
		return nil
	}
	sort.Strings(heads)
	seed := struct {
		Version int      `json:"version"`
		Head    string   `json:"head"`
		Heads   []string `json:"heads"`
	}{Version: 1, Head: heads[0], Heads: heads}
	data, err := json.Marshal(seed)
	if err != nil {
		return nil
	}
	return data
}

// githubHostFromAPIBase returns the web host for blob links, derived from the
// REST api_base. Public api.github.com → github.com; GHE bases keep their host.
func githubHostFromAPIBase(apiBase string) string {
	if strings.TrimRight(apiBase, "/") == strings.TrimRight(githubDefaultAPIBase, "/") {
		return "github.com"
	}
	if u, err := url.Parse(apiBase); err == nil && u.Host != "" {
		return u.Host
	}
	return "github.com"
}

// githubBlobLink builds a web link to the blob at a commit. With line>0 it
// appends the "#L<line>" fragment; otherwise it omits it.
func githubBlobLink(host, owner, repo, commit, path string, line int) string {
	if host == "" || commit == "" || path == "" {
		return ""
	}
	// Archive provenance is virtual (`outer.zip!inner/file`). GitHub can only
	// link to the outer blob; the full virtual path remains in metadata.Path.
	outer := strings.SplitN(path, "!", 2)[0]
	if strings.HasPrefix(outer, "/") {
		return ""
	}
	clean := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(outer)), "./")
	if clean == ".." || strings.HasPrefix(clean, "../") {
		return ""
	}
	parts := strings.Split(clean, "/")
	for i := range parts {
		parts[i] = url.PathEscape(parts[i])
	}
	escapedPath := strings.Join(parts, "/")
	link := fmt.Sprintf("https://%s/%s/%s/blob/%s/%s", host, url.PathEscape(owner), url.PathEscape(repo), url.PathEscape(commit), escapedPath)
	if line > 0 {
		link += fmt.Sprintf("#L%d", line)
	}
	return link
}

func githubVisibility(repo githubRepoRef) string {
	if repo.Private {
		return "private"
	}
	if repo.Visibility != "" {
		return repo.Visibility
	}
	return "public"
}

// githubIncrementalFlushInterval throttles per-repo state flushes. Each flush
// marshals the whole org's state, so flushing every repo costs O(N^2) over a
// long run; a crash loses at most this much progress instead.
const githubIncrementalFlushInterval = 30 * time.Second
