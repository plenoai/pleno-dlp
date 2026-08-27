// GitHub connector. Single-file Lambda-handler shape: auth, fetch, emit.
//
// Scanning is always full-history: a changed repo gets ONE bare git clone over
// smart HTTP, followed by a local walk of every safe history ref. Incremental
// repos with unchanged REST metadata first receive a lightweight smart-Git
// pull-ref advertisement; identical snapshots skip clone and walk. Git smart
// HTTP does NOT consume the GitHub REST rate limit. The history walk itself
// lives in github_history.go.
//
// API-call accounting:
//   - Repo enumeration: 1 REST call (single repo) or N paginated REST calls
//     (org listing).
//   - Per repo: 0 REST calls for code. Cold/changed metadata: 1 smart-HTTP
//     clone. Unchanged metadata: 1 ref advertisement, plus a clone only when
//     GitHub pull refs changed or the advertisement failed.
//   - include_comments: REST issue-comment + pull-review-comment pagination.
//
// Comments: GitHub models pull requests as issues, so issue comments cover PR
// conversation comments; pull review comments cover inline code-review
// comments. Comments are REST-based.
//
// Auth: Personal Access Token or GitHub App installation token. REST requests
// send `Authorization: Bearer <token>`; git smart-HTTP clones authenticate as
// `x-access-token:<token>` HTTP Basic (works for PATs and App installation
// tokens alike). The public REST API base is `https://api.github.com`; GitHub
// Enterprise installs override it via `api_base` (e.g.
// `https://ghe.example/api/v3`), from which the clone host is derived.

package connectors

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	githubDefaultAPIBase = "https://api.github.com"
	githubRequestTimeout = 60 * time.Second
	githubAppJWTLifetime = 9 * time.Minute
	githubAppRefreshSkew = 5 * time.Minute

	// githubScanModeHistory is the value stamped into persisted incremental
	// state (Mode field). It is the only scan mode; the constant survives the
	// removal of tree mode solely to tag state so legacy non-history state is
	// recognised and ignored on load. See githubRepoIncrementalState.Mode.
	githubScanModeHistory = "history"
)

func init() {
	Register("github", Connector{
		SourceType:  sources.SourceGitHub,
		Scan:        scanGitHub,
		Verify:      verifyGitHub,
		Fingerprint: fingerprintGitHub,
	})
}

// scanGitHub is the Lambda handler. Scanning is always full-history; the walk
// lives in scanGitHubHistory (github_history.go). cfg keys:
//   - token         PAT, sent as Bearer (REST) / x-access-token (clone)
//   - app_id        GitHub App ID, used with app_installation_id + private key
//   - app_installation_id GitHub App installation ID
//   - app_private_key GitHub App PEM private key
//   - app_private_key_file path to GitHub App PEM private key
//   - org           org login (mutually exclusive with repo)
//   - repo          owner/name single-repo scope
//   - api_base      override https://api.github.com
//   - include_comments scan issue comments and pull review comments
//   - clone_url_template advanced/test-only override for the clone URL; see
//     deriveCloneURL. Use "{owner}" and "{repo}" placeholders, or a bare local
//     path for tests injecting a fixture repo.
func scanGitHub(ctx context.Context, cfg Config, emit Emit) error {
	delete(cfg, configKeyIncrementalPartialSafe)
	auth, err := newGitHubAuthProvider(cfg)
	if err != nil {
		return err
	}
	org, repo := cfg["org"], cfg["repo"]
	hasGists := len(splitNonEmptyLines(cfg["gist_urls"])) > 0 || parseBool(cfg["include_authenticated_gists"])
	if org == "" && repo == "" && !hasGists {
		return errors.New("github: either org, repo, explicit gists, or authenticated gists must be set")
	}
	if org != "" && repo != "" {
		return errors.New("github: org and repo are mutually exclusive")
	}
	if repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("github: repo must be in owner/name form, got %q", repo)
		}
	}
	apiBase := cfg.Get("api_base", githubDefaultAPIBase)
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return fmt.Errorf("github: invalid api_base %q", apiBase)
	}
	if err := validateGitHubAuthenticatedTransport(apiBase, auth != nil); err != nil {
		return err
	}
	if _, err := githubCommentsSince(cfg, time.Now()); err != nil {
		return err
	}
	var historyErr error
	if org != "" || repo != "" {
		historyErr = scanGitHubHistory(ctx, cfg, auth, apiBase, org, repo, emit)
	}
	var gistErr error
	if hasGists {
		gistErr = scanGitHubGists(ctx, cfg, auth, apiBase, emit)
	}
	if hasGists {
		// Repository state safety does not certify independent gist surfaces.
		delete(cfg, configKeyIncrementalPartialSafe)
	}
	return errors.Join(historyErr, gistErr)
}

// verifyGitHub hits GET /user for PATs and GET /installation/repositories for
// GitHub App auth. 200 → verified, 401/403 → not verified.
func verifyGitHub(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", githubDefaultAPIBase)
	path := "/user"
	var auth githubTokenProvider
	if secret != "" {
		auth = staticGitHubToken(secret)
	} else {
		var err error
		auth, err = newGitHubAuthProvider(cfg)
		if err != nil {
			return false, err
		}
		path = "/installation/repositories"
	}
	cli := newGitHubClient(apiBase, auth)
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("github: verify unexpected status %s", resp.Status)
	}
}

// --- internal types ---

type githubRepoRef struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
	PushedAt      string `json:"pushed_at"`
	UpdatedAt     string `json:"updated_at"`
	Size          int64  `json:"size"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
	HasWiki       bool   `json:"has_wiki"`
}

type githubMemberRef struct {
	Login string `json:"login"`
}

type githubIssueComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	HTMLURL   string `json:"html_url"`
	Issue     string `json:"issue_url"`
	UpdatedAt string `json:"updated_at"`
}

type githubPullReviewComment struct {
	ID        int64  `json:"id"`
	Body      string `json:"body"`
	Path      string `json:"path"`
	Position  int    `json:"position"`
	HTMLURL   string `json:"html_url"`
	PullURL   string `json:"pull_request_url"`
	UpdatedAt string `json:"updated_at"`
}

type githubIssue struct {
	Number      int       `json:"number"`
	Title       string    `json:"title"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	UpdatedAt   string    `json:"updated_at"`
	PullRequest *struct{} `json:"pull_request"`
}

type githubPullRequest struct {
	Number    int    `json:"number"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	HTMLURL   string `json:"html_url"`
	UpdatedAt string `json:"updated_at"`
}

type githubIncrementalState struct {
	Version          int                                              `json:"version"`
	ScopeFingerprint string                                           `json:"scope_fingerprint,omitempty"`
	CompleteRuns     int                                              `json:"complete_runs,omitempty"`
	Tombstones       map[string]githubStateTombstone                  `json:"tombstones,omitempty"`
	Surfaces         map[string]map[string]githubRepoIncrementalState `json:"surfaces,omitempty"`
	// Repos accepts the version-1 state written before source-unit namespaces.
	// New state is written exclusively through Surfaces.
	Repos map[string]githubRepoIncrementalState `json:"repos,omitempty"`
}

type githubRepoIncrementalState struct {
	StableID        string `json:"stable_id,omitempty"`
	LastSeen        string `json:"last_seen,omitempty"`
	UnobservedSince string `json:"unobserved_since,omitempty"`
	UnobservedRuns  int    `json:"unobserved_runs,omitempty"`
	// Mode tags the state shape so legacy tree-mode state (written by builds
	// from before tree mode was removed: Mode empty or "tree", carrying a
	// blobs map and no RefHeads) is recognised and ignored. Current state is
	// always Mode == "history": RefHeads carries the per-ref head shas from
	// the previous full-history walk, used to seed the next walk's stop-set.
	// A run that loads non-history state ignores it, performs one full rescan,
	// and rewrites the repo entry as history state — so old states migrate
	// transparently on the next scan. Mode is retained (rather than dropped)
	// precisely to make that one-time migration detectable; once all persisted
	// state has been rewritten it is always "history".
	Mode       string            `json:"mode,omitempty"`
	Visibility string            `json:"visibility,omitempty"`
	RefHeads   map[string]string `json:"ref_heads,omitempty"`
	// PullRefHeads is the exact advertised refs/pull/<number>/{head,merge}
	// snapshot observed by the completed history scan. Unlike RefHeads, an
	// empty non-nil map is meaningful: it proves the remote advertisement was
	// checked and contained no pull refs. Missing legacy state stays nil and
	// forces one full clone before unchanged skipping is allowed.
	PullRefHeads map[string]string `json:"pull_ref_heads"`
	// PushedAt is the repo's pushed_at as observed in the enumeration that
	// drove the walk which produced RefHeads. A later run with the same value
	// still verifies PullRefHeads through a lightweight smart-Git advertisement
	// before skipping clone+walk, because fork PR refs can move independently
	// of the base repository's pushed_at. Empty legacy state disables the skip.
	PushedAt           string                                   `json:"pushed_at,omitempty"`
	Policy             string                                   `json:"policy,omitempty"`
	IssueComments      map[string]githubCommentIncrementalState `json:"issue_comments,omitempty"`
	PullReviewComments map[string]githubCommentIncrementalState `json:"pull_review_comments,omitempty"`
	Issues             map[string]githubEntityIncrementalState  `json:"issues,omitempty"`
	PullRequests       map[string]githubEntityIncrementalState  `json:"pull_requests,omitempty"`
}

type githubStateTombstone struct {
	StableID        string `json:"stable_id,omitempty"`
	LastName        string `json:"last_name"`
	FirstUnobserved string `json:"first_unobserved"`
	CompleteRuns    int    `json:"complete_runs"`
}

func githubHistoryPolicy(cfg Config) string {
	h := sha256.New()
	// v2 adds tags and GitHub pull-request refs to the advertised history
	// roots. Invalidate v1 checkpoints once so incremental callers do not skip
	// the first scan that can discover commits reachable only from those refs.
	writeFingerprint(h, "github-history-policy-v2")
	for _, key := range []string{
		"include_commit_metadata", "skip_merge_commits", "trufflehog_compatible", "include_git_archives", "include_git_binaries",
		"git_artifact_max_bytes", "archive_max_expanded_bytes", "archive_max_files",
		"archive_max_depth", "archive_timeout",
	} {
		writeFingerprint(h, key)
		writeFingerprint(h, cfg[key])
	}
	return hex.EncodeToString(h.Sum(nil))
}

type githubCommentIncrementalState struct {
	UpdatedAt string `json:"updated_at"`
	Path      string `json:"path,omitempty"`
	Position  int    `json:"position,omitempty"`
}

type githubEntityIncrementalState struct {
	UpdatedAt string `json:"updated_at"`
	TitleHash string `json:"title_hash,omitempty"`
	BodyHash  string `json:"body_hash,omitempty"`
}

func githubTextHash(text string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(text)))
	return hex.EncodeToString(sum[:])
}

// loadGitHubIncrementalState parses persisted per-repo incremental state.
// Migration: state written by builds from before tree mode was removed has
// per-repo entries with Mode empty or "tree" and a now-deleted blobs map but
// no RefHeads. Those entries unmarshal cleanly here (unknown JSON fields are
// dropped, the blobs map simply has no destination field). The history walk
// then treats any entry whose Mode != "history" as absent: it performs one
// full rescan for that repo and rewrites the entry as history state, so old
// states migrate transparently on the next scan without erroring.
func loadGitHubIncrementalState(raw string) (*githubIncrementalState, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var state githubIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("github: parse incremental source state: %w", err)
	}
	if state.Version > 3 {
		return nil, fmt.Errorf("github: incremental source state version %d is newer than supported version 3", state.Version)
	}
	if state.Repos == nil {
		state.Repos = map[string]githubRepoIncrementalState{}
	}
	if state.Surfaces == nil {
		state.Surfaces = map[string]map[string]githubRepoIncrementalState{}
	}
	if state.Tombstones == nil {
		state.Tombstones = map[string]githubStateTombstone{}
	}
	state.Version = 3
	if _, ok := state.Surfaces["repository-history"]; !ok {
		state.Surfaces["repository-history"] = state.Repos
	}
	if _, ok := state.Surfaces["repository-wiki"]; !ok {
		state.Surfaces["repository-wiki"] = map[string]githubRepoIncrementalState{}
	}
	return &state, nil
}

func githubListRepos(ctx context.Context, cli *githubClient, org, repo string) ([]githubRepoRef, error) {
	if repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		path := fmt.Sprintf("/repos/%s/%s", parts[0], parts[1])
		var rr githubRepoRef
		if _, err := cli.getJSON(ctx, path, &rr); err != nil {
			return nil, fmt.Errorf("github: get repo %s: %w", repo, err)
		}
		if rr.Owner.Login == "" {
			rr.Owner.Login = parts[0]
		}
		if rr.Name == "" {
			rr.Name = parts[1]
		}
		return []githubRepoRef{rr}, nil
	}
	var repos []githubRepoRef
	next := fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", org)
	for next != "" {
		var page []githubRepoRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("github: list org %s repos: %w", org, err)
		}
		repos = append(repos, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return repos, nil
}

func githubEnumerateRepos(ctx context.Context, cli *githubClient, cfg Config, org, repo string) ([]githubRepoRef, []githubRepoRef, map[string]int, error) {
	if repo == "" {
		if exactRepos, ok := githubExactIncludedRepos(cfg); ok {
			var repos []githubRepoRef
			for _, exactRepo := range exactRepos {
				listed, err := githubListRepos(ctx, cli, org, exactRepo)
				if err != nil {
					return nil, nil, nil, err
				}
				repos = append(repos, listed...)
			}
			selected, skipped, err := githubFilterRepos(cfg, repos)
			return selected, repos, skipped, err
		}
	}
	repos, err := githubListRepos(ctx, cli, org, repo)
	if err != nil {
		return nil, nil, nil, err
	}
	if repo == "" && parseBool(cfg["expand_members"]) {
		members, err := githubListMembers(ctx, cli, org)
		if err != nil {
			return nil, nil, nil, err
		}
		for _, member := range members {
			memberRepos, err := githubListUserRepos(ctx, cli, member.Login)
			if err != nil {
				return nil, nil, nil, err
			}
			repos = append(repos, memberRepos...)
		}
	}
	selected, skipped, err := githubFilterRepos(cfg, repos)
	return selected, repos, skipped, err
}

func githubExactIncludedRepos(cfg Config) ([]string, bool) {
	includes := splitNonEmptyLines(cfg["include_repo_globs"])
	if len(includes) == 0 {
		return nil, false
	}
	for _, include := range includes {
		parts := strings.Split(include, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || strings.ContainsAny(include, `*?[\`) {
			return nil, false
		}
	}
	return includes, true
}

func githubListMembers(ctx context.Context, cli *githubClient, org string) ([]githubMemberRef, error) {
	var members []githubMemberRef
	next := fmt.Sprintf("/orgs/%s/members?per_page=100", org)
	for next != "" {
		var page []githubMemberRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("github: list org %s members: %w", org, err)
		}
		members = append(members, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return members, nil
}

func githubListUserRepos(ctx context.Context, cli *githubClient, login string) ([]githubRepoRef, error) {
	var repos []githubRepoRef
	next := fmt.Sprintf("/users/%s/repos?per_page=100&type=owner", login)
	for next != "" {
		var page []githubRepoRef
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("github: list member %s repos: %w", login, err)
		}
		repos = append(repos, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return repos, nil
}

func githubFilterRepos(cfg Config, repos []githubRepoRef) ([]githubRepoRef, map[string]int, error) {
	includes := splitNonEmptyLines(cfg["include_repo_globs"])
	excludes := splitNonEmptyLines(cfg["exclude_repo_globs"])
	includeForks := parseBoolDefault(cfg, "include_forks", true)
	includeArchived := parseBoolDefault(cfg, "include_archived", true)
	seen := make(map[string]struct{}, len(repos))
	filtered := make([]githubRepoRef, 0, len(repos))
	skipped := map[string]int{}
	for _, r := range repos {
		key := r.Owner.Login + "/" + r.Name
		if _, ok := seen[key]; ok {
			skipped["duplicate"]++
			continue
		}
		seen[key] = struct{}{}
		if r.Fork && !includeForks {
			skipped["fork"]++
			continue
		}
		if r.Archived && !includeArchived {
			skipped["archived"]++
			continue
		}
		included, err := githubGlobMatch(includes, key, len(includes) == 0)
		if err != nil {
			return nil, nil, fmt.Errorf("github: invalid include repo glob: %w", err)
		}
		if !included {
			skipped["not-included"]++
			continue
		}
		excluded, err := githubGlobMatch(excludes, key, false)
		if err != nil {
			return nil, nil, fmt.Errorf("github: invalid exclude repo glob: %w", err)
		}
		if excluded {
			skipped["excluded"]++
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered, skipped, nil
}

func githubGlobMatch(globs []string, value string, fallback bool) (bool, error) {
	for _, glob := range globs {
		matched, err := path.Match(glob, value)
		if err != nil {
			return false, err
		}
		if matched {
			return true, nil
		}
	}
	return fallback, nil
}

func splitNonEmptyLines(raw string) []string {
	var out []string
	for _, item := range strings.Split(raw, "\n") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parseBoolDefault(cfg Config, key string, fallback bool) bool {
	raw, ok := cfg[key]
	if !ok || strings.TrimSpace(raw) == "" {
		return fallback
	}
	return parseBool(raw)
}

func scanGitHubCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, since string, emit Emit) error {
	if err := scanGitHubIssueCommentsIncremental(ctx, cli, repo, prev, hasPrev, next, since, emit); err != nil {
		return err
	}
	return scanGitHubPullReviewCommentsIncremental(ctx, cli, repo, prev, hasPrev, next, since, emit)
}

func scanGitHubIssueCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, since string, emit Emit) error {
	if next.IssueComments == nil {
		next.IssueComments = make(map[string]githubCommentIncrementalState, len(prev.IssueComments))
		for id, state := range prev.IssueComments {
			next.IssueComments[id] = state
		}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/issues/comments?per_page=100", repo.Owner.Login, repo.Name)
	if since != "" {
		nextPath += "&since=" + url.QueryEscape(since)
	}
	for nextPath != "" {
		var page []githubIssueComment
		resp, err := cli.getJSON(ctx, nextPath, &page)
		if err != nil {
			return fmt.Errorf("github: list issue comments for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		for _, c := range page {
			id := strconv.FormatInt(c.ID, 10)
			next.IssueComments[id] = githubCommentIncrementalState{UpdatedAt: c.UpdatedAt}
			if hasPrev {
				if old, ok := prev.IssueComments[id]; ok && old.UpdatedAt == c.UpdatedAt {
					continue
				}
			}
			body := strings.TrimSpace(c.Body)
			if body == "" {
				continue
			}
			if err := emit([]byte(body), sources.Metadata{
				GitHub: &sources.GitHubMeta{
					Repository: repo.Owner.Login + "/" + repo.Name,
					Link:       c.HTMLURL,
					File:       fmt.Sprintf("issue-comment:%d", c.ID),
					Owner:      repo.Owner.Login,
					Repo:       repo.Name,
					Path:       fmt.Sprintf("issue-comment:%d", c.ID),
				},
			}); err != nil {
				return err
			}
		}
		nextPath = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func scanGitHubPullReviewCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, since string, emit Emit) error {
	if next.PullReviewComments == nil {
		next.PullReviewComments = make(map[string]githubCommentIncrementalState, len(prev.PullReviewComments))
		for id, state := range prev.PullReviewComments {
			next.PullReviewComments[id] = state
		}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/pulls/comments?per_page=100", repo.Owner.Login, repo.Name)
	if since != "" {
		nextPath += "&since=" + url.QueryEscape(since)
	}
	for nextPath != "" {
		var page []githubPullReviewComment
		resp, err := cli.getJSON(ctx, nextPath, &page)
		if err != nil {
			return fmt.Errorf("github: list pull review comments for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		for _, c := range page {
			path := c.Path
			if path == "" {
				path = fmt.Sprintf("pull-review-comment:%d", c.ID)
			}
			id := strconv.FormatInt(c.ID, 10)
			next.PullReviewComments[id] = githubCommentIncrementalState{
				UpdatedAt: c.UpdatedAt,
				Path:      path,
				Position:  c.Position,
			}
			if hasPrev {
				if old, ok := prev.PullReviewComments[id]; ok && old.UpdatedAt == c.UpdatedAt && old.Path == path && old.Position == c.Position {
					continue
				}
			}
			body := strings.TrimSpace(c.Body)
			if body == "" {
				continue
			}
			if err := emit([]byte(body), sources.Metadata{
				GitHub: &sources.GitHubMeta{
					Repository: repo.Owner.Login + "/" + repo.Name,
					Link:       c.HTMLURL,
					File:       path,
					Line:       c.Position,
					Owner:      repo.Owner.Login,
					Repo:       repo.Name,
					Path:       path,
				},
			}); err != nil {
				return err
			}
		}
		nextPath = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func githubCommentsSince(cfg Config, now time.Time) (string, error) {
	raw := cfg.Get("comments_timeframe_days", "0")
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 {
		return "", fmt.Errorf("github: comments_timeframe_days must be non-negative, got %q", raw)
	}
	if days == 0 {
		return "", nil
	}
	return now.UTC().AddDate(0, 0, -days).Format(time.RFC3339), nil
}

func githubCollaborationSince(cfg Config, now time.Time) (string, error) {
	raw := cfg.Get("collab_timeframe_days", "0")
	days, err := strconv.Atoi(raw)
	if err != nil || days < 0 {
		return "", fmt.Errorf("github: collab_timeframe_days must be non-negative, got %q", raw)
	}
	if days == 0 {
		return "", nil
	}
	return now.UTC().AddDate(0, 0, -days).Format(time.RFC3339), nil
}

func scanGitHubIssuesIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, next *githubRepoIncrementalState, since string, emit Emit) error {
	if next.Issues == nil {
		next.Issues = make(map[string]githubEntityIncrementalState, len(prev.Issues))
		for id, state := range prev.Issues {
			next.Issues[id] = state
		}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/issues?state=all&sort=updated&direction=asc&per_page=100", repo.Owner.Login, repo.Name)
	if since != "" {
		nextPath += "&since=" + url.QueryEscape(since)
	}
	for nextPath != "" {
		var page []githubIssue
		resp, err := cli.getJSON(ctx, nextPath, &page)
		if err != nil {
			return fmt.Errorf("github: list issues for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		for _, item := range page {
			if item.PullRequest != nil {
				continue
			}
			id := strconv.Itoa(item.Number)
			old, hadOld := prev.Issues[id]
			state := githubEntityIncrementalState{UpdatedAt: item.UpdatedAt, TitleHash: githubTextHash(item.Title), BodyHash: githubTextHash(item.Body)}
			next.Issues[id] = state
			if hadOld && old.UpdatedAt == item.UpdatedAt {
				continue
			}
			if err := emitGitHubEntityPartsChanged(repo, "issue", item.Number, item.Title, item.Body, item.HTMLURL, old, hadOld, emit); err != nil {
				return err
			}
		}
		nextPath = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func scanGitHubPullRequestsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, next *githubRepoIncrementalState, since string, emit Emit) error {
	if next.PullRequests == nil {
		next.PullRequests = make(map[string]githubEntityIncrementalState, len(prev.PullRequests))
		for id, state := range prev.PullRequests {
			next.PullRequests[id] = state
		}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/pulls?state=all&sort=updated&direction=desc&per_page=100", repo.Owner.Login, repo.Name)
	ordered := true
	var previousUpdated time.Time
	cutoff, cutoffErr := time.Parse(time.RFC3339, since)
	if since != "" && cutoffErr != nil {
		return fmt.Errorf("github: invalid PR timeframe %q: %w", since, cutoffErr)
	}
	pages, timeframeItems, avoidedPages := 0, 0, 0
	for nextPath != "" {
		var page []githubPullRequest
		resp, err := cli.getJSON(ctx, nextPath, &page)
		if err != nil {
			return fmt.Errorf("github: list pull requests for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		pages++
		allOlder := len(page) > 0
		for _, item := range page {
			updated, parseErr := time.Parse(time.RFC3339, item.UpdatedAt)
			if parseErr != nil {
				ordered = false
				allOlder = false
			}
			if parseErr == nil && !previousUpdated.IsZero() && updated.After(previousUpdated) {
				ordered = false
			}
			if parseErr == nil {
				previousUpdated = updated
			}
			if since != "" && parseErr == nil && updated.Before(cutoff) {
				timeframeItems++
				continue
			}
			allOlder = false
			id := strconv.Itoa(item.Number)
			old, hadOld := prev.PullRequests[id]
			state := githubEntityIncrementalState{UpdatedAt: item.UpdatedAt, TitleHash: githubTextHash(item.Title), BodyHash: githubTextHash(item.Body)}
			next.PullRequests[id] = state
			if hadOld && old.UpdatedAt == item.UpdatedAt {
				continue
			}
			if err := emitGitHubEntityPartsChanged(repo, "pull_request", item.Number, item.Title, item.Body, item.HTMLURL, old, hadOld, emit); err != nil {
				return err
			}
		}
		next := parseLinkHeader(resp.Header.Get("Link"))
		if since != "" && allOlder && ordered && next != "" {
			avoidedPages = 1 // lower bound; GitHub Link does not expose remaining count reliably
			break
		}
		nextPath = next
	}
	if timeframeItems > 0 || avoidedPages > 0 {
		fmt.Fprintf(os.Stderr, "github: PR timeframe %s/%s fetched %d pages, skipped %d old items, avoided at least %d pages\n", repo.Owner.Login, repo.Name, pages, timeframeItems, avoidedPages)
	}
	return nil
}

func emitGitHubEntityPartsChanged(repo githubRepoRef, entity string, number int, title, body, link string, old githubEntityIncrementalState, hadOld bool, emit Emit) error {
	for _, part := range []struct{ name, text string }{{"title", title}, {"body", body}} {
		text := strings.TrimSpace(part.text)
		if text == "" {
			continue
		}
		if hadOld && ((part.name == "title" && old.TitleHash == githubTextHash(text)) || (part.name == "body" && old.BodyHash == githubTextHash(text))) {
			continue
		}
		path := fmt.Sprintf("%s:%d:%s", entity, number, part.name)
		if err := emit([]byte(text), sources.Metadata{GitHub: &sources.GitHubMeta{
			Repository: repo.Owner.Login + "/" + repo.Name,
			Owner:      repo.Owner.Login, Repo: repo.Name, Link: link,
			File: path, Path: path, Entity: entity, Number: number, Part: part.name, Visibility: githubVisibility(repo),
		}}); err != nil {
			return err
		}
	}
	return nil
}

// fingerprintGitHub opts out of the whole-source unchanged fast path. GitHub's
// synthetic pull refs can move without changing repository REST metadata, so
// no metadata-only fingerprint can safely prove full-history coverage. The
// connector performs one normal repository enumeration instead, then checks a
// lightweight pull-ref advertisement only for repositories whose pushed_at is
// unchanged; identical snapshots still skip their clone and history walk.
func fingerprintGitHub(context.Context, Config) (string, error) {
	return "", nil
}

func writeFingerprint(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
}

// --- rate-limit-aware HTTP client ---

type githubTokenProvider interface {
	Token(context.Context) (string, error)
}

type staticGitHubToken string

func (s staticGitHubToken) Token(context.Context) (string, error) {
	return string(s), nil
}

type githubAppTokenProvider struct {
	base           string
	appID          string
	installationID string
	key            *rsa.PrivateKey
	http           *http.Client
	now            func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	// refreshDone is non-nil while one caller owns the installation-token
	// request. Other callers wait on this channel without holding mu, so their
	// own contexts can cancel independently without starting duplicate refreshes.
	refreshDone chan struct{}
}

type githubAppTokenResp struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

func newGitHubAuthProvider(cfg Config) (githubTokenProvider, error) {
	token := cfg["token"]
	hasAppConfig := cfg["app_id"] != "" || cfg["app_installation_id"] != "" || cfg["app_private_key"] != "" || cfg["app_private_key_file"] != ""
	if token != "" && hasAppConfig {
		return nil, errors.New("github: --token and GitHub App credentials are mutually exclusive")
	}
	if token != "" {
		return staticGitHubToken(token), nil
	}
	if !hasAppConfig {
		return nil, errors.New("github: --token or GitHub App credentials are required")
	}
	return newGitHubAppTokenProvider(cfg)
}

func newGitHubAppTokenProvider(cfg Config) (*githubAppTokenProvider, error) {
	appID := strings.TrimSpace(cfg["app_id"])
	installationID := strings.TrimSpace(cfg["app_installation_id"])
	if appID == "" {
		return nil, errors.New("github: app_id is required for GitHub App auth")
	}
	if installationID == "" {
		return nil, errors.New("github: app_installation_id is required for GitHub App auth")
	}
	keyPEM, err := resolveGitHubAppPrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	key, err := parseGitHubAppPrivateKey([]byte(keyPEM))
	if err != nil {
		return nil, err
	}
	base := cfg.Get("api_base", githubDefaultAPIBase)
	if u, err := url.Parse(base); err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("github: invalid api_base %q", base)
	}
	return &githubAppTokenProvider{
		base:           base,
		appID:          appID,
		installationID: installationID,
		key:            key,
		http:           &http.Client{Timeout: githubRequestTimeout},
		now:            time.Now,
	}, nil
}

func resolveGitHubAppPrivateKey(cfg Config) (string, error) {
	if cfg["app_private_key"] != "" && cfg["app_private_key_file"] != "" {
		return "", errors.New("github: app_private_key and app_private_key_file are mutually exclusive")
	}
	if cfg["app_private_key"] != "" {
		return normalizePEMNewlines(cfg["app_private_key"]), nil
	}
	if cfg["app_private_key_file"] == "" {
		return "", errors.New("github: app_private_key or app_private_key_file is required for GitHub App auth")
	}
	data, err := os.ReadFile(cfg["app_private_key_file"])
	if err != nil {
		return "", fmt.Errorf("github: read app_private_key_file: %w", err)
	}
	return string(data), nil
}

func normalizePEMNewlines(s string) string {
	if strings.Contains(s, `\n`) && !strings.Contains(s, "\n") {
		return strings.ReplaceAll(s, `\n`, "\n")
	}
	return s
}

func parseGitHubAppPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("github: app private key must be PEM encoded")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("github: parse app private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: app private key must be RSA")
	}
	return key, nil
}

func (p *githubAppTokenProvider) Token(ctx context.Context) (string, error) {
	for {
		p.mu.Lock()
		now := p.now()
		if p.token != "" && now.Before(p.expiresAt.Add(-githubAppRefreshSkew)) {
			token := p.token
			p.mu.Unlock()
			return token, nil
		}
		if done := p.refreshDone; done != nil {
			p.mu.Unlock()
			select {
			case <-done:
				// Re-check the cache under the mutex. If the owner failed, exactly
				// one awakened waiter becomes the next refresh owner.
				continue
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
		p.refreshDone = make(chan struct{})
		done := p.refreshDone
		p.mu.Unlock()

		token, expiresAt, err := p.fetchInstallationToken(ctx, now)
		p.mu.Lock()
		if err == nil {
			p.token = token
			p.expiresAt = expiresAt
		}
		p.refreshDone = nil
		close(done)
		p.mu.Unlock()
		if err != nil {
			return "", err
		}
		return token, nil
	}
}

func (p *githubAppTokenProvider) fetchInstallationToken(ctx context.Context, now time.Time) (string, time.Time, error) {
	jwt, err := p.signJWT(now)
	if err != nil {
		return "", time.Time{}, err
	}
	path := fmt.Sprintf("%s/app/installations/%s/access_tokens", strings.TrimRight(p.base, "/"), url.PathEscape(p.installationID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, path, bytes.NewReader([]byte("{}")))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	resp, err := p.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return "", time.Time{}, fmt.Errorf("github: create installation token -> %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}
	var out githubAppTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, fmt.Errorf("github: decode installation token: %w", err)
	}
	if out.Token == "" {
		return "", time.Time{}, errors.New("github: installation token response missing token")
	}
	expiresAt, err := time.Parse(time.RFC3339, out.ExpiresAt)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("github: parse installation token expires_at: %w", err)
	}
	return out.Token, expiresAt, nil
}

func (p *githubAppTokenProvider) signJWT(now time.Time) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(githubAppJWTLifetime).Unix(),
		"iss": p.appID,
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("github: sign app jwt: %w", err)
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type githubClient struct {
	base string
	auth githubTokenProvider
	http *http.Client

	// testSleep replaces real sleeps in tests. nil in production.
	testSleep func(time.Duration)
	coord     *githubRateCoordinator
}
type githubAPIError struct {
	Status int
	Kind   string
	Path   string
	Err    error
	Detail string
}

func (e *githubAPIError) Error() string {
	return fmt.Sprintf("github API %s %s (status=%d): %s", e.Kind, e.Path, e.Status, e.Detail)
}
func (e *githubAPIError) Unwrap() error { return e.Err }

type githubRateCoordinator struct {
	mu              sync.Mutex
	nextAllowed     time.Time
	constrained     bool
	permit          chan struct{}
	waits           atomic.Int64
	throttles       atomic.Int64
	requestSeq      atomic.Uint64
	lastResponseSeq uint64
	resetEpoch      int64
}

func newGitHubClient(base string, auth githubTokenProvider) *githubClient {
	if base == "" {
		base = githubDefaultAPIBase
	}
	c := &githubClient{
		base:  base,
		auth:  auth,
		coord: &githubRateCoordinator{permit: make(chan struct{}, 1)},
	}
	c.coord.permit <- struct{}{}
	c.http = &http.Client{Timeout: githubRequestTimeout, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if _, err := c.validateURL(req.URL); err != nil {
			return err
		}
		return nil
	}}
	return c
}

func (c *githubClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		target, err := c.resolveURL(path)
		if err != nil {
			return nil, err
		} // reject before token lookup/header attachment
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.auth != nil {
			token, err := c.auth.Token(ctx)
			if err != nil {
				return nil, err
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
		}
		release, err := c.acquireRatePermit(ctx)
		if err != nil {
			return nil, err
		}
		seq := c.coord.requestSeq.Add(1)
		resp, err := c.http.Do(req)
		release()
		if err != nil {
			// Transport-level failures (connection reset, timeout, DNS) are
			// transient: record into lastErr and retry within maxAttempts,
			// surfacing the final error via the lastErr return below on
			// exhaustion. Context cancellation/deadline is terminal — return
			// immediately so it is never masked by a later retry sentinel.
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		c.observeRateLimit(resp, seq)
		// idempotent な GET に対する 5xx (502/503/504 など) は GitHub 側の
		// 一時的な障害が大半で、 巨大 org の数時間 scan を 1 回の Bad Gateway
		// で投げ捨てる損が大きすぎる。 rate-limit と同じ backoff で retry する。
		// POST/PATCH 等の副作用ありは重複生成リスクがあるので GET に限定。
		if method == http.MethodGet && resp.StatusCode >= 500 && resp.StatusCode < 600 {
			wait := githubTransientBackoff(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
			}
			if wait <= 0 {
				wait = time.Second
			}
			logGitHubWait(fmt.Sprintf("%d from GET %s", resp.StatusCode, path), wait, attempt+1, maxAttempts)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		if githubRateLimited(resp) {
			wait := githubBackoff(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
			}
			if wait <= 0 {
				wait = time.Second
			}
			logGitHubWait(fmt.Sprintf("rate limited on %s %s", method, path), wait, attempt+1, maxAttempts)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("github: exhausted retries against rate limit")
	}
	return nil, lastErr
}

func (c *githubClient) acquireRatePermit(ctx context.Context) (func(), error) {
	c.coord.mu.Lock()
	constrained := c.coord.constrained
	c.coord.mu.Unlock()
	if !constrained {
		return func() {}, nil
	}
	start := time.Now()
	select {
	case <-c.coord.permit:
		wait := time.Since(start)
		c.coord.waits.Add(wait.Nanoseconds())
		c.coord.throttles.Add(1)
		return func() { c.coord.permit <- struct{}{} }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func (c *githubClient) rateCoordinationStats() (time.Duration, int64) {
	return time.Duration(c.coord.waits.Load()), c.coord.throttles.Load()
}

func (c *githubClient) getJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	const maxAttempts = 5
	var lastResp *http.Response
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := c.do(ctx, http.MethodGet, path, nil)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, &githubAPIError{Kind: "transport", Path: path, Err: err, Detail: err.Error()}
		}
		lastResp = resp
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			_ = resp.Body.Close()
			// c.do は 5xx GET なら既に retry 済み。 ここに来た 5xx は
			// retry-exhausted なので上位に返す。
			kind := "status"
			if resp.StatusCode == http.StatusNotFound {
				kind = "missing"
			} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				kind = "auth"
			}
			return resp, &githubAPIError{Status: resp.StatusCode, Kind: kind, Path: path, Detail: strings.TrimSpace(string(body))}
		}
		if out == nil {
			return resp, nil
		}
		decErr := json.NewDecoder(resp.Body).Decode(out)
		_ = resp.Body.Close()
		if decErr == nil {
			return resp, nil
		}
		lastErr = fmt.Errorf("github: decode %s: %w", path, decErr)
		// body 読み込み中に peer 側が stream を切るケース (HTTP/2 GOAWAY,
		// stream CANCEL、 connection reset、 unexpected EOF) は transient。
		// 数時間 scan で 1 page を投げ捨てる価値が無いので、 exponential
		// backoff で同じ page を再取得する。
		if !isTransientHTTPReadErr(decErr) {
			return resp, lastErr
		}
		wait := time.Duration(1<<attempt) * time.Second
		if wait > time.Minute {
			wait = time.Minute
		}
		if c.testSleep != nil {
			c.testSleep(wait)
			continue
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
	}
	return lastResp, lastErr
}

func isTransientHTTPReadErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "stream error") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "GOAWAY")
}

func (c *githubClient) resolveURL(p string) (string, error) {
	base, err := url.Parse(c.base)
	if err != nil {
		return "", err
	}
	if base.User != nil {
		return "", errors.New("github: api_base must not contain credentials")
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		u, err := url.Parse(p)
		if err != nil {
			return "", err
		}
		if _, err := c.validateURL(u); err != nil {
			return "", err
		}
		return u.String(), nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u, err := url.Parse(strings.TrimRight(c.base, "/") + p)
	if err != nil {
		return "", err
	}
	if _, err := c.validateURL(u); err != nil {
		return "", err
	}
	return u.String(), nil
}

func canonicalOrigin(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	}
	return strings.ToLower(u.Scheme) + "://" + host
}
func (c *githubClient) validateURL(u *url.URL) (*url.URL, error) {
	base, err := url.Parse(c.base)
	if err != nil {
		return nil, err
	}
	if base.User != nil || u.User != nil {
		return nil, errors.New("github: credentials in API URL are forbidden")
	}
	if canonicalOrigin(u) != canonicalOrigin(base) {
		return nil, errors.New("github: rejected URL outside canonical API origin")
	}
	raw := strings.ToLower(u.EscapedPath())
	if strings.Contains(raw, "%2f") || strings.Contains(raw, "%5c") || strings.Contains(raw, "%2e") {
		return nil, errors.New("github: encoded separators or traversal in API URL")
	}
	decoded, err := url.PathUnescape(u.EscapedPath())
	if err != nil {
		return nil, err
	}
	clean := path.Clean(decoded)
	if strings.Contains(decoded, "\\") || clean == ".." || strings.HasPrefix(clean, "../") {
		return nil, errors.New("github: traversal in API URL")
	}
	baseDecoded, _ := url.PathUnescape(base.EscapedPath())
	basePath := strings.TrimRight(path.Clean(baseDecoded), "/")
	if basePath != "" && basePath != "." && clean != basePath && !strings.HasPrefix(clean, basePath+"/") {
		return nil, errors.New("github: rejected URL outside API path base")
	}
	return u, nil
}

func (c *githubClient) waitForBucket(ctx context.Context) error {
	c.coord.mu.Lock()
	until := c.coord.nextAllowed
	c.coord.mu.Unlock()
	if until.IsZero() {
		return nil
	}
	delay := time.Until(until)
	if delay <= 0 {
		return nil
	}
	if c.testSleep != nil {
		c.testSleep(delay)
		return nil
	}
	// この待ちは quota 全消費後の reset 待ちで、 数十分に及び得る。
	// サイレントに寝ると外部からはハングと区別できないので必ず残す。
	if delay > 30*time.Second {
		fmt.Fprintf(os.Stderr, "pleno-dlp: github rate limit exhausted, sleeping %s until reset\n", delay.Round(time.Second))
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// logGitHubWait surfaces retry sleeps on stderr. Multi-hour scans have died
// silently here before; the ECS runbook decides liveness from log output, so
// every sleep longer than a heartbeat must leave a trace.
func logGitHubWait(cause string, wait time.Duration, attempt, maxAttempts int) {
	fmt.Fprintf(os.Stderr, "pleno-dlp: github %s, waiting %s before retry (attempt %d/%d)\n",
		cause, wait.Round(time.Second), attempt, maxAttempts)
}

func (c *githubClient) observeRateLimit(resp *http.Response, sequences ...uint64) {
	rem := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")
	n, err := strconv.Atoi(rem)
	if err != nil {
		return
	}
	c.coord.mu.Lock()
	defer c.coord.mu.Unlock()
	seq := uint64(0)
	if len(sequences) > 0 {
		seq = sequences[0]
	}
	epoch := int64(0)
	if reset != "" {
		epoch, _ = strconv.ParseInt(reset, 10, 64)
	}
	if epoch < c.coord.resetEpoch || (epoch == c.coord.resetEpoch && seq > 0 && seq < c.coord.lastResponseSeq) {
		return
	}
	if epoch > c.coord.resetEpoch {
		c.coord.resetEpoch = epoch
	}
	if seq > c.coord.lastResponseSeq {
		c.coord.lastResponseSeq = seq
	}
	if n <= 10 {
		c.coord.constrained = true
	} else if n > 50 {
		c.coord.constrained = false
		c.coord.nextAllowed = time.Time{}
	}
	if n == 0 && reset != "" {
		if ts, e := strconv.ParseInt(reset, 10, 64); e == nil {
			c.coord.nextAllowed = time.Unix(ts, 0)
		}
	}
}

func githubRateLimited(resp *http.Response) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	if resp.StatusCode == http.StatusForbidden {
		if resp.Header.Get("Retry-After") != "" {
			return true
		}
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return true
		}
	}
	return false
}

// githubBackoffCap bounds a single retry sleep. GitHub's primary rate limit
// resets within the hour, so an honest Retry-After / X-RateLimit-Reset never
// legitimately exceeds this; anything larger is a clock skew or a bogus
// header, and sleeping on it would wedge the scan for hours.
const githubBackoffCap = 65 * time.Minute

// githubTransientBackoff is intentionally separate from rate-limit backoff.
// Successful and 5xx GitHub responses routinely carry X-RateLimit-Reset as
// quota metadata; treating that header as a retry instruction can turn one
// 502 into an hour-long sleep. Only an explicit Retry-After controls a 5xx
// retry, and transient waits stay bounded like TruffleHog's retry client.
func githubTransientBackoff(resp *http.Response, attempt int) time.Duration {
	const cap = time.Minute
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return minDuration(time.Duration(secs)*time.Second, cap)
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return minDuration(d, cap)
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	return minDuration(d, cap)
}

func githubBackoff(resp *http.Response, attempt int) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return minDuration(time.Duration(secs)*time.Second, githubBackoffCap)
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return minDuration(d, githubBackoffCap)
			}
		}
	}
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(ts, 0)); d > 0 {
				return minDuration(d, githubBackoffCap)
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// parseLinkHeader extracts the rel="next" cursor URL from a GitHub /
// GitLab Link header. Shared by both connectors so we don't duplicate
// the parser. Both quoted (`rel="next"`) and unquoted (`rel=next`)
// forms are matched.
func parseLinkHeader(header string) string {
	if header == "" {
		return ""
	}
	for _, segment := range strings.Split(header, ",") {
		s := strings.TrimSpace(segment)
		if !strings.HasPrefix(s, "<") {
			continue
		}
		end := strings.Index(s, ">")
		if end < 0 {
			continue
		}
		u := s[1:end]
		for _, p := range strings.Split(s[end+1:], ";") {
			kv := strings.TrimSpace(p)
			if kv == `rel="next"` || kv == `rel=next` {
				return u
			}
		}
	}
	return ""
}
