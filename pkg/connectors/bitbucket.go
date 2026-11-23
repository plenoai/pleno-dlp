// Bitbucket Cloud connector. Single-file Lambda-handler shape.
//
// Surface: workspace or single-repo default-branch files, optional full Git
// history (HTTPS clone link through the shared scanRemoteGitRepo walker;
// the x-token-auth user for access tokens, the username for app
// passwords), and optional workspace snippets. Issues / PRs / pipelines /
// wikis are out of scope.
//
// Auth: Bearer token (workspace / repository access token) takes priority
// over HTTP Basic (username + app password). Both are accepted; the
// caller picks one.
//
// Pagination: Bitbucket returns absolute "next" URLs in JSON response
// bodies. We follow them verbatim, but only while they stay on the API
// origin so credentials are never sent to another host.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	bitbucketDefaultAPIBase      = "https://api.bitbucket.org/2.0"
	bitbucketDefaultMaxFileBytes = int64(5 * 1024 * 1024)
	bitbucketRequestTimeout      = 60 * time.Second
	// bitbucketTokenCloneUser is the HTTPS clone user for access tokens.
	bitbucketTokenCloneUser = "x-token-auth"
)

func init() {
	Register("bitbucket", Connector{
		SourceType:  sources.SourceBitbucket,
		Scan:        scanBitbucket,
		Verify:      verifyBitbucket,
		Fingerprint: fingerprintBitbucket,
	})
}

// scanBitbucket is the Lambda handler. cfg keys:
//   - token             Bearer access token (mutually exclusive with app_password)
//   - username          required when using app_password
//   - app_password      HTTP Basic password (mutually exclusive with token)
//   - workspace         workspace slug (mutually exclusive with repo)
//   - repo              workspace/slug single-repo scope
//   - api_base          override https://api.bitbucket.org/2.0
//   - max_file_bytes    per-file size cap
//   - concurrency       per-repo file fanout
//   - history           clone each repo and walk every branch and tag
//   - include_snippets  scan the workspace's snippets
func scanBitbucket(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	appPassword := cfg["app_password"]
	username := cfg["username"]
	if token == "" && appPassword == "" {
		return errors.New("bitbucket: token or app_password is required")
	}
	if token != "" && appPassword != "" {
		return errors.New("bitbucket: token and app_password are mutually exclusive")
	}
	if appPassword != "" && username == "" {
		return errors.New("bitbucket: username is required when using app_password auth")
	}
	workspace, repo := cfg["workspace"], cfg["repo"]
	if workspace == "" && repo == "" {
		return errors.New("bitbucket: workspace or repo must be set")
	}
	apiBase := cfg.Get("api_base", bitbucketDefaultAPIBase)
	if err := requireSecureEndpoint("bitbucket", apiBase); err != nil {
		return err
	}
	maxBytes := bitbucketDefaultMaxFileBytes
	if v := cfg["max_file_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}
	concurrency := 4
	if v := cfg["concurrency"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrency = n
		}
	}

	cli := newBitbucketClient(apiBase, username, appPassword, token)
	repos, err := bitbucketListRepos(ctx, cli, workspace, repo)
	if err != nil {
		return err
	}
	previousState, err := loadBitbucketIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &bitbucketIncrementalState{Version: 1, Repos: map[string]bitbucketRepoIncrementalState{}}
	if previousState == nil {
		previousState = &bitbucketIncrementalState{Version: 1, Repos: map[string]bitbucketRepoIncrementalState{}}
	}
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		repoKey := r.FullName
		if repoKey == "" {
			repoKey = r.workspaceSlug() + "/" + r.Name
		}
		prevRepo, hasPrevRepo := previousState.Repos[repoKey]
		nextRepo, err := scanBitbucketRepoIncremental(ctx, cli, r, prevRepo, hasPrevRepo, maxBytes, concurrency, emit)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
		if parseBool(cfg["history"]) {
			target := remoteGitRepo{Key: repoKey, CloneURL: r.httpsCloneURL()}
			if strings.HasPrefix(target.CloneURL, "https://") || strings.HasPrefix(target.CloneURL, "http://") {
				target.Username, target.Password = bitbucketCloneAuth(token, username, appPassword)
			}
			history, err := scanRemoteGitRepo(ctx, "bitbucket", target, prevRepo.History, emit)
			if err != nil {
				return err
			}
			nextRepo.History = history
		}
		nextState.Repos[repoKey] = nextRepo
	}
	if parseBool(cfg["include_snippets"]) {
		ws := workspace
		if ws == "" {
			ws, _, _ = strings.Cut(repo, "/")
		}
		nextState.Snippets = map[string]string{}
		if err := scanBitbucketSnippets(ctx, cli, ws, previousState.Snippets, nextState.Snippets, emit); err != nil {
			return err
		}
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("bitbucket: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return nil
}

func verifyBitbucket(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", bitbucketDefaultAPIBase)
	if err := requireSecureEndpoint("bitbucket", apiBase); err != nil {
		return false, err
	}
	cli := newBitbucketClient(apiBase, "", "", secret)
	resp, err := cli.do(ctx, http.MethodGet, "/2.0/user", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("bitbucket: verify unexpected status %s", resp.Status)
	}
}

func fingerprintBitbucket(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	appPassword := cfg["app_password"]
	username := cfg["username"]
	if token == "" && appPassword == "" {
		return "", errors.New("bitbucket: token or app_password is required")
	}
	workspace, repo := cfg["workspace"], cfg["repo"]
	if workspace == "" && repo == "" {
		return "", errors.New("bitbucket: workspace or repo must be set")
	}
	apiBase := cfg.Get("api_base", bitbucketDefaultAPIBase)
	if err := requireSecureEndpoint("bitbucket", apiBase); err != nil {
		return "", err
	}
	// Non-default branches and snippets have no cheap fingerprint; hashing
	// only default-branch files would let --incremental skip their changes.
	if parseBool(cfg["history"]) || parseBool(cfg["include_snippets"]) {
		return "", nil
	}
	cli := newBitbucketClient(apiBase, username, appPassword, token)
	repos, err := bitbucketListRepos(ctx, cli, workspace, repo)
	if err != nil {
		return "", err
	}
	sort.Slice(repos, func(i, j int) bool { return repos[i].FullName < repos[j].FullName })

	h := sha256.New()
	writeFingerprint(h, "bitbucket-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, workspace)
	writeFingerprint(h, repo)
	for _, r := range repos {
		if err := fingerprintBitbucketRepo(ctx, h, cli, r); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintBitbucketRepo(ctx context.Context, h hash.Hash, cli *bitbucketClient, repo bitbucketRepoRef) error {
	branch := repo.MainBranch.Name
	if branch == "" {
		return nil
	}
	ws := repo.workspaceSlug()
	slug := repo.Name
	writeFingerprint(h, ws+"/"+slug)
	writeFingerprint(h, branch)
	entries, err := bitbucketListSrcEntries(ctx, cli, ws, slug, branch)
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, entry := range entries {
		if entry.Type != "commit_file" {
			continue
		}
		writeFingerprint(h, entry.Path)
		writeFingerprint(h, entry.Commit.Hash)
		writeFingerprint(h, strconv.FormatInt(entry.Size, 10))
	}
	return nil
}

// --- internal types ---

type bitbucketRepoRef struct {
	FullName  string `json:"full_name"`
	Name      string `json:"name"`
	Workspace struct {
		Slug string `json:"slug"`
	} `json:"workspace"`
	MainBranch struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	IsPrivate bool `json:"is_private"`
	Links     struct {
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
}

// httpsCloneURL returns the repository's HTTPS clone link with any
// embedded userinfo (Bitbucket adds "user@") removed; credentials are
// supplied separately by scanRemoteGitRepo.
func (r *bitbucketRepoRef) httpsCloneURL() string {
	for _, c := range r.Links.Clone {
		if c.Name != "https" {
			continue
		}
		u, err := url.Parse(c.Href)
		if err != nil {
			return ""
		}
		u.User = nil
		return u.String()
	}
	return ""
}

type bitbucketSnippet struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	UpdatedOn string `json:"updated_on"`
	Files     map[string]struct {
		Links struct {
			Self struct {
				Href string `json:"href"`
			} `json:"self"`
		} `json:"links"`
	} `json:"files"`
}

// UnmarshalJSON accepts Bitbucket's numeric or string snippet ids.
func (s *bitbucketSnippet) UnmarshalJSON(b []byte) error {
	type alias bitbucketSnippet
	var raw struct {
		alias
		ID json.RawMessage `json:"id"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = bitbucketSnippet(raw.alias)
	s.ID = strings.Trim(string(raw.ID), `"`)
	return nil
}

func (r *bitbucketRepoRef) workspaceSlug() string {
	if r.Workspace.Slug != "" {
		return r.Workspace.Slug
	}
	if i := strings.IndexByte(r.FullName, '/'); i > 0 {
		return r.FullName[:i]
	}
	return ""
}

type bitbucketSrcEntry struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	Commit struct {
		Hash string `json:"hash"`
	} `json:"commit"`
}

type bitbucketPaginatedSrc struct {
	Values []bitbucketSrcEntry `json:"values"`
	Next   string              `json:"next,omitempty"`
}

type bitbucketPaginatedRepos struct {
	Values []bitbucketRepoRef `json:"values"`
	Next   string             `json:"next,omitempty"`
}

type bitbucketIncrementalState struct {
	Version int                                      `json:"version"`
	Repos   map[string]bitbucketRepoIncrementalState `json:"repos"`
	// Snippets maps snippet id -> updated_on.
	Snippets map[string]string `json:"snippets,omitempty"`
}

type bitbucketRepoIncrementalState struct {
	Branch string                                   `json:"branch,omitempty"`
	Files  map[string]bitbucketFileIncrementalState `json:"files,omitempty"`
	// History is the git source's per-ref state for the cloned repository.
	History json.RawMessage `json:"history,omitempty"`
}

type bitbucketFileIncrementalState struct {
	Hash string `json:"hash,omitempty"`
	Size int64  `json:"size,omitempty"`
}

func loadBitbucketIncrementalState(raw string) (*bitbucketIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state bitbucketIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("bitbucket: parse incremental source state: %w", err)
	}
	if state.Repos == nil {
		state.Repos = map[string]bitbucketRepoIncrementalState{}
	}
	return &state, nil
}

func bitbucketListRepos(ctx context.Context, cli *bitbucketClient, workspace, repo string) ([]bitbucketRepoRef, error) {
	if repo != "" {
		parts := strings.SplitN(repo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("bitbucket: repo must be in workspace/slug form, got %q", repo)
		}
		ws, slug := parts[0], parts[1]
		path := fmt.Sprintf("/2.0/repositories/%s/%s", ws, slug)
		var rr bitbucketRepoRef
		if _, err := cli.getJSON(ctx, path, &rr); err != nil {
			return nil, fmt.Errorf("bitbucket: get repo %s/%s: %w", ws, slug, err)
		}
		if rr.Workspace.Slug == "" {
			rr.Workspace.Slug = ws
		}
		if rr.Name == "" {
			rr.Name = slug
		}
		return []bitbucketRepoRef{rr}, nil
	}
	var repos []bitbucketRepoRef
	next := fmt.Sprintf("/2.0/repositories/%s?pagelen=100", workspace)
	for next != "" {
		var page bitbucketPaginatedRepos
		if _, err := cli.getJSON(ctx, next, &page); err != nil {
			return nil, fmt.Errorf("bitbucket: list workspace %s repos: %w", workspace, err)
		}
		repos = append(repos, page.Values...)
		next = page.Next
	}
	return repos, nil
}

func scanBitbucketRepoIncremental(ctx context.Context, cli *bitbucketClient, repo bitbucketRepoRef, prev bitbucketRepoIncrementalState, hasPrev bool, maxBytes int64, concurrency int, emit Emit) (bitbucketRepoIncrementalState, error) {
	branch := repo.MainBranch.Name
	nextRepo := bitbucketRepoIncrementalState{Branch: branch, Files: map[string]bitbucketFileIncrementalState{}}
	if branch == "" {
		return nextRepo, nil
	}
	ws := repo.workspaceSlug()
	slug := repo.Name
	entries, err := bitbucketListSrcEntries(ctx, cli, ws, slug, branch)
	if err != nil {
		return bitbucketRepoIncrementalState{}, err
	}

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)
	for _, entry := range entries {
		entry := entry
		if entry.Type != "commit_file" {
			continue
		}
		if entry.Size > maxBytes {
			continue
		}
		state := bitbucketStateForFile(entry)
		nextRepo.Files[entry.Path] = state
		if hasPrev && prev.Files != nil && prev.Files[entry.Path] == state {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return bitbucketRepoIncrementalState{}, gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return emitBitbucketFile(gctx, cli, ws, slug, branch, entry, maxBytes, emit)
		})
	}
	if err := g.Wait(); err != nil {
		return bitbucketRepoIncrementalState{}, err
	}
	return nextRepo, nil
}

func bitbucketStateForFile(entry bitbucketSrcEntry) bitbucketFileIncrementalState {
	return bitbucketFileIncrementalState{Hash: entry.Commit.Hash, Size: entry.Size}
}

func bitbucketListSrcEntries(ctx context.Context, cli *bitbucketClient, ws, slug, branch string) ([]bitbucketSrcEntry, error) {
	var entries []bitbucketSrcEntry
	next := fmt.Sprintf("/2.0/repositories/%s/%s/src/%s/?pagelen=100", ws, slug, branch)
	for next != "" {
		var page bitbucketPaginatedSrc
		if _, err := cli.getJSON(ctx, next, &page); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, err
			}
			return nil, fmt.Errorf("bitbucket: src listing %s/%s@%s: %w", ws, slug, branch, err)
		}
		entries = append(entries, page.Values...)
		next = page.Next
	}
	return entries, nil
}

func emitBitbucketFile(ctx context.Context, cli *bitbucketClient, workspace, slug, branch string, entry bitbucketSrcEntry, maxBytes int64, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := fmt.Sprintf("/2.0/repositories/%s/%s/src/%s/%s", workspace, slug, branch, entry.Path)
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 512))
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return nil
	}
	return emit(data, sources.Metadata{
		Bitbucket: &sources.BitbucketMeta{
			Workspace: workspace,
			Repo:      slug,
			Path:      entry.Path,
			Branch:    branch,
		},
	})
}

// --- HTTP client ---

type bitbucketClient struct {
	base        string
	username    string
	appPassword string
	bearerToken string
	http        *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	testSleep func(time.Duration)
}

func newBitbucketClient(base, username, appPassword, bearerToken string) *bitbucketClient {
	if base == "" {
		base = bitbucketDefaultAPIBase
	}
	// Every request path already carries its own /2.0 prefix; keeping it on
	// the base as well produced https://api.bitbucket.org/2.0/2.0/... .
	base = strings.TrimSuffix(strings.TrimRight(base, "/"), "/2.0")
	return &bitbucketClient{
		base:        base,
		username:    username,
		appPassword: appPassword,
		bearerToken: bearerToken,
		http:        authenticatedHTTPClient(bitbucketRequestTimeout),
	}
}

func (c *bitbucketClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		target, err := c.url(path)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		c.setAuth(req)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := bitbucketBackoff(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			continue
		}
		return resp, nil
	}
	if lastErr == nil {
		lastErr = errors.New("bitbucket: exhausted retries against rate limit")
	}
	return nil, lastErr
}

func (c *bitbucketClient) getJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("bitbucket: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("bitbucket: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

func (c *bitbucketClient) setAuth(req *http.Request) {
	if c.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerToken)
	} else if c.username != "" || c.appPassword != "" {
		req.SetBasicAuth(c.username, c.appPassword)
	}
}

func (c *bitbucketClient) url(p string) (string, error) {
	return apiURL("bitbucket", c.base, p)
}

func (c *bitbucketClient) waitForBucket(ctx context.Context) error {
	c.mu.Lock()
	until := c.nextAllowed
	c.mu.Unlock()
	if until.IsZero() {
		return nil
	}
	delay := time.Until(until)
	if delay <= 0 {
		return nil
	}
	return c.sleep(ctx, delay)
}

func (c *bitbucketClient) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		d = time.Second
	}
	if c.testSleep != nil {
		c.testSleep(d)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

func bitbucketBackoff(resp *http.Response, attempt int) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
			return time.Duration(secs) * time.Second
		}
		if t, err := http.ParseTime(v); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}

// scanBitbucketSnippets lists /2.0/snippets/{workspace} and emits every file
// of each snippet whose updated_on changed since the previous run.
func scanBitbucketSnippets(ctx context.Context, cli *bitbucketClient, workspace string, prev, next map[string]string, emit Emit) error {
	if workspace == "" {
		return errors.New("bitbucket: workspace is required for snippets")
	}
	listPath := fmt.Sprintf("/2.0/snippets/%s?pagelen=100", url.PathEscape(workspace))
	for listPath != "" {
		var page struct {
			Values []bitbucketSnippet `json:"values"`
			Next   string             `json:"next,omitempty"`
		}
		if _, err := cli.getJSON(ctx, listPath, &page); err != nil {
			return fmt.Errorf("bitbucket: list snippets: %w", err)
		}
		for _, sn := range page.Values {
			if err := ctx.Err(); err != nil {
				return err
			}
			if sn.UpdatedOn != "" && prev[sn.ID] == sn.UpdatedOn {
				next[sn.ID] = sn.UpdatedOn
				continue
			}
			var full bitbucketSnippet
			if _, err := cli.getJSON(ctx, fmt.Sprintf("/2.0/snippets/%s/%s", url.PathEscape(workspace), url.PathEscape(sn.ID)), &full); err != nil {
				return fmt.Errorf("bitbucket: get snippet %s: %w", sn.ID, err)
			}
			names := make([]string, 0, len(full.Files))
			for name := range full.Files {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, name := range names {
				href := full.Files[name].Links.Self.Href
				if href == "" {
					href = fmt.Sprintf("/2.0/snippets/%s/%s/files/%s", url.PathEscape(workspace), url.PathEscape(sn.ID), url.PathEscape(name))
				}
				data, err := bitbucketFetchRaw(ctx, cli, href, bitbucketDefaultMaxFileBytes)
				if err != nil {
					return err
				}
				if err := emit(data, sources.Metadata{Bitbucket: &sources.BitbucketMeta{
					Workspace: workspace,
					Path:      "snippet:" + sn.ID + ":" + name,
				}}); err != nil {
					return err
				}
			}
			next[sn.ID] = sn.UpdatedOn
		}
		listPath = page.Next
	}
	return nil
}

func bitbucketFetchRaw(ctx context.Context, cli *bitbucketClient, path string, maxBytes int64) ([]byte, error) {
	resp, err := cli.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("bitbucket: GET snippet file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("bitbucket: GET snippet file -> %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// bitbucketCloneAuth returns the HTTPS clone credentials: access tokens
// use the fixed x-token-auth user, app passwords the account username.
func bitbucketCloneAuth(token, user, pass string) (string, string) {
	if token != "" {
		return bitbucketTokenCloneUser, token
	}
	return user, pass
}
