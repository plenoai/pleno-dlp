// GitHub full-history scan. Per repo: one bare git clone over smart HTTP, then
// a full-history walk of every ref via the git source (AllBranches=true). The
// git source owns the diff walk; this file only clones, bridges its Chunk
// channel into the connector Emit (rewriting GitMeta provenance into the
// GitHubMeta shape downstream formatters expect), and threads incremental
// state. See github.go's file header for the API-call accounting.
package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

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

// scanGitHubHistory clones every enumerated repo and walks its full history.
// Per-repo failures (clone error, walk error) are tolerated so the org walk
// continues; context cancellation/deadline is terminal.
func scanGitHubHistory(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase, org, repo string, emit Emit) error {
	cli := newGitHubClient(apiBase, auth)
	repos, err := githubListRepos(ctx, cli, org, repo)
	if err != nil {
		return err
	}
	previousState, err := loadGitHubIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	if previousState == nil {
		previousState = &githubIncrementalState{Version: 1, Repos: map[string]githubRepoIncrementalState{}}
	}
	nextState := &githubIncrementalState{Version: 1, Repos: map[string]githubRepoIncrementalState{}}

	template := cfg["clone_url_template"]
	host := githubHostFromAPIBase(apiBase)

	var lastFlush time.Time
	for i, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		repoKey := r.Owner.Login + "/" + r.Name
		fmt.Fprintf(os.Stderr, "github: scan [%d/%d] %s\n", i+1, len(repos), repoKey)
		prevRepo := previousState.Repos[repoKey]
		nextRepo, err := scanGitHubRepoHistory(ctx, cfg, auth, apiBase, host, template, r, prevRepo, emit)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Per-repo failures are tolerated — keep walking the org. The repo
			// is still scanned up to the previous run's heads, so carry that
			// state forward; dropping it would force a full rescan next run.
			fmt.Fprintf(os.Stderr, "WARN: github: scan failed for %s, skipping: %v\n", repoKey, err)
			if prevRepo.Mode == githubScanModeHistory {
				nextState.Repos[repoKey] = prevRepo
			}
			continue
		}
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
			if err := scanGitHubCommentsIncremental(ctx, cli, r, commentPrev, hasCommentPrev, &nextRepo, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				// Code walked to the new heads but comments didn't finish:
				// keep the new RefHeads and the previous comment cursors so
				// neither side full-rescans next run. A partially emitted
				// comment page may re-emit then; dedup downstream absorbs it.
				fmt.Fprintf(os.Stderr, "WARN: github: comment scan failed for %s, skipping: %v\n", repoKey, err)
				merged := nextRepo
				merged.IssueComments = commentPrev.IssueComments
				merged.PullReviewComments = commentPrev.PullReviewComments
				nextState.Repos[repoKey] = merged
				continue
			}
		}
		nextState.Repos[repoKey] = nextRepo
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
					fmt.Fprintf(os.Stderr, "WARN: github incremental flush failed after %s: %v\n", repoKey, ferr)
				}
				lastFlush = time.Now()
			}
		}
	}
	if data, err := json.Marshal(nextState); err == nil {
		cfg[configKeyIncrementalNextState] = string(data)
	}
	return nil
}

// scanGitHubRepoHistory clones one repo bare and walks it. It returns the
// repo's next incremental state (RefHeads after the walk).
func scanGitHubRepoHistory(ctx context.Context, cfg Config, auth githubTokenProvider, apiBase, host, template string, repo githubRepoRef, prev githubRepoIncrementalState, emit Emit) (githubRepoIncrementalState, error) {
	cloneURL, err := deriveCloneURL(apiBase, repo.Owner.Login, repo.Name, template)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}

	dir, err := os.MkdirTemp("", "pleno-gh-clone-")
	if err != nil {
		return githubRepoIncrementalState{}, fmt.Errorf("github: mktemp for clone: %w", err)
	}
	defer os.RemoveAll(dir)

	cloneOpts := &gogit.CloneOptions{URL: cloneURL}
	if basic, err := githubCloneAuth(ctx, auth, cloneURL); err != nil {
		return githubRepoIncrementalState{}, err
	} else if basic != nil {
		cloneOpts.Auth = basic
	}
	if _, err := gogit.PlainCloneContext(ctx, dir, true, cloneOpts); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return githubRepoIncrementalState{}, err
		}
		return githubRepoIncrementalState{}, fmt.Errorf("github: clone %s/%s: %w", repo.Owner.Login, repo.Name, err)
	}

	visibility := githubVisibility(repo)
	src := &gitsource.Source{}
	gitCfg := gitsource.Config{Repo: dir, AllBranches: true}
	raw, err := json.Marshal(gitCfg)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	// The git source's verify flag only stamps chunk.Verify, which we discard
	// when re-emitting via the connector Emit (the engine sets verify on the
	// connector path). false is correct here.
	if err := src.Init(ctx, "github", 0, 0, false, raw, 1); err != nil {
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
	ch := make(chan *sources.Chunk, 64)
	walkErr := make(chan error, 1)
	go func() {
		walkErr <- src.Chunks(ctx, ch)
		close(ch)
	}()

	link := func(commit, path string, line int) string {
		return githubBlobLink(host, repo.Owner.Login, repo.Name, commit, path, line)
	}
	var emitErr error
	for c := range ch {
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
		if err := emit(c.Data, meta); err != nil {
			emitErr = err
		}
	}
	if err := <-walkErr; err != nil {
		return githubRepoIncrementalState{}, err
	}
	if emitErr != nil {
		return githubRepoIncrementalState{}, emitErr
	}

	next := githubRepoIncrementalState{
		Mode:       githubScanModeHistory,
		Visibility: visibility,
	}
	heads, err := gitRefHeads(dir)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	next.RefHeads = heads
	return next, nil
}

// githubCloneAuth builds HTTP Basic auth for the clone. The token is fetched
// once per clone. A local-path clone URL (no scheme/host) needs no auth.
func githubCloneAuth(ctx context.Context, auth githubTokenProvider, cloneURL string) (*githttp.BasicAuth, error) {
	if u, err := url.Parse(cloneURL); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, nil // local path or non-URL — go-git clones without auth
	}
	if auth == nil {
		return nil, nil
	}
	token, err := auth.Token(ctx)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, nil
	}
	return &githttp.BasicAuth{Username: "x-access-token", Password: token}, nil
}

// gitRefHeads reads the post-clone ref → sha map (branches and remotes) so the
// next run can stop the walk at these heads.
func gitRefHeads(dir string) (map[string]string, error) {
	repo, err := gogit.PlainOpen(dir)
	if err != nil {
		return nil, fmt.Errorf("github: reopen clone: %w", err)
	}
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
	link := fmt.Sprintf("https://%s/%s/%s/blob/%s/%s", host, owner, repo, commit, path)
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
