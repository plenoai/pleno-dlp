// GitHub full-history scan. Per repo: one bare git clone over smart HTTP, then
// a full-history walk of every ref via the git source (AllBranches=true). The
// git source owns the diff walk; this file only clones, bridges its Chunk
// channel into the connector Emit (rewriting GitMeta provenance into the
// GitHubMeta shape downstream formatters expect), and threads incremental
// state. See github.go's file header for the API-call accounting.
package connectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

// githubCloneBlobFilterLimit bounds the clone's protocol-level blob filter
// (--filter=blob:limit). It must stay equal to maxBlobSize in
// pkg/sources/git/git.go (unexported there, so this is a documented
// duplicate rather than a shared import): the git walk discards any blob
// bigger than that constant regardless of how it got fetched, so filtering
// oversized blobs out of the clone itself — instead of downloading them and
// then throwing them away during the walk — saves both bandwidth and, for
// the native-git path, the delta-resolution memory those blobs would have
// cost git during the clone.
const githubCloneBlobFilterLimit int64 = 50 * 1024 * 1024 // 50 MiB — keep equal to gitsource.maxBlobSize

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

	orgStart := time.Now()
	failed := 0
	skipped := 0
	var lastFlush time.Time
	for i, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		repoKey := r.Owner.Login + "/" + r.Name
		sizeNote := ""
		if r.Size > 0 {
			sizeNote = " (" + formatBytes(uint64(r.Size)*1024) + ")"
		}
		fmt.Fprintf(os.Stderr, "github: scan [%d/%d] %s%s\n", i+1, len(repos), repoKey, sizeNote)
		repoStart := time.Now()
		prevRepo := previousState.Repos[repoKey]
		var nextRepo githubRepoIncrementalState
		if githubRepoUnchanged(prevRepo, r) {
			// No push since the walk that produced prevRepo.RefHeads: cloning
			// would fetch the same refs and the seeded walk would emit nothing.
			// Carry the state; only Visibility can have moved without a push
			// (comments can too — their scan below still runs on this path).
			skipped++
			nextRepo = prevRepo
			nextRepo.Visibility = githubVisibility(r)
			fmt.Fprintf(os.Stderr, "github: scan [%d/%d] %s unchanged since last run (pushed_at %s), clone skipped\n", i+1, len(repos), repoKey, r.PushedAt)
		} else {
			var err error
			nextRepo, err = scanGitHubRepoHistory(ctx, cfg, auth, apiBase, host, template, r, prevRepo, emit)
			if err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				// Per-repo failures are tolerated — keep walking the org. The repo
				// is still scanned up to the previous run's heads, so carry that
				// state forward; dropping it would force a full rescan next run.
				failed++
				fmt.Fprintf(os.Stderr, "WARN: github: scan failed for %s after %s, skipping: %v\n", repoKey, time.Since(repoStart).Round(time.Second), err)
				if prevRepo.Mode == githubScanModeHistory {
					nextState.Repos[repoKey] = prevRepo
				}
				continue
			}
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
		fmt.Fprintf(os.Stderr, "github: scan [%d/%d] %s done in %s\n", i+1, len(repos), repoKey, time.Since(repoStart).Round(time.Second))
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
	fmt.Fprintf(os.Stderr, "github: org scan complete: %d repos, %d unchanged (clone skipped), %d failed, took %s\n", len(repos), skipped, failed, time.Since(orgStart).Round(time.Second))
	return nil
}

// githubRepoUnchanged reports whether the repo received no push since the
// previous history walk, so the clone+walk can be skipped and prev carried
// forward. It demands history-mode state with RefHeads (legacy tree-mode state
// must take the one-time full rescan) and a non-empty pushed_at on both sides:
// the enumeration reports pushed_at as null for never-pushed repos, and state
// written by builds predating PushedAt carries none — neither proves anything.
func githubRepoUnchanged(prev githubRepoIncrementalState, r githubRepoRef) bool {
	return prev.Mode == githubScanModeHistory &&
		len(prev.RefHeads) > 0 &&
		prev.PushedAt != "" &&
		prev.PushedAt == r.PushedAt
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

	repoKey := repo.Owner.Login + "/" + repo.Name
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
	hb.setPhase("walk")
	walkStart := time.Now()

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
		walkErr <- src.Chunks(ctx, ch)
		close(ch)
	}()

	link := func(commit, path string, line int) string {
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
	fmt.Fprintf(os.Stderr, "github: walk %s done: %d chunks in %s\n", repoKey, hb.chunks.Load(), time.Since(walkStart).Round(time.Second))

	next := githubRepoIncrementalState{
		Mode:       githubScanModeHistory,
		Visibility: visibility,
		PushedAt:   repo.PushedAt,
	}
	heads, err := gitRefHeads(gitRepo)
	if err != nil {
		return githubRepoIncrementalState{}, err
	}
	next.RefHeads = heads
	return next, nil
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
// scaling problem #265 reports; it also has no partial-clone filter support,
// so it always fetches full history regardless of blob size.
//
// The native path additionally passes --filter=blob:limit=<N> (see
// githubCloneBlobFilterLimit) so oversized blobs the walk would discard
// anyway are never fetched. go-git's fallback has no equivalent for this.
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
	cloneOpts := &gogit.CloneOptions{URL: cloneURL, Progress: progress}
	if token != "" {
		if u, err := url.Parse(cloneURL); err == nil && u.Scheme != "" && u.Host != "" {
			cloneOpts.Auth = &githttp.BasicAuth{Username: "x-access-token", Password: token}
		}
	}
	_, err := gogit.PlainCloneContext(ctx, dir, true, cloneOpts)
	return err
}

// cloneWithNativeGit execs `git clone --bare --filter=blob:limit=<N>`.
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
	cmd.Stderr = progress
	// Never prompt interactively: a hung terminal prompt on a bad/expired
	// token would look identical to a stalled clone from the heartbeat's
	// point of view. Fail fast instead.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	cmd.Env = append(cmd.Env, nativeGitAuthEnv(cloneURL, token)...)
	if err := cmd.Run(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return redactCloneError(err, token)
	}
	return nil
}

// nativeGitCloneArgs builds the argv for the native bare clone with the
// blob-size filter (#265). Split out from cloneWithNativeGit so the exact
// flags/ordering can be asserted in a unit test without executing git.
func nativeGitCloneArgs(cloneURL, dir string) []string {
	return []string{
		"clone",
		"--bare",
		fmt.Sprintf("--filter=blob:limit=%d", githubCloneBlobFilterLimit),
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
	if token == "" {
		return err
	}
	return errors.New(strings.ReplaceAll(err.Error(), token, "REDACTED"))
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
