// GitHub connector. Single-file Lambda-handler shape: auth, fetch, emit.
//
// Surface: org or single-repo default-branch blobs. Issues / PRs land in
// follow-ups; the Config keys for them are accepted today and ignored so
// invocation shape stays stable.
//
// Auth: Personal Access Token via `Authorization: Bearer <token>` against
// the public REST API (`https://api.github.com`). GitHub Enterprise
// installs override the base via `api_base`.

package connectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	githubDefaultAPIBase      = "https://api.github.com"
	githubDefaultMaxBlobBytes = int64(5 * 1024 * 1024)
	githubRequestTimeout      = 60 * time.Second
)

func init() {
	Register("github", Connector{
		SourceType: sources.SourceGitHub,
		Scan:       scanGitHub,
		Verify:     verifyGitHub,
	})
}

// scanGitHub is the Lambda handler. cfg keys:
//   - token         (required) PAT, sent as Bearer
//   - org           org login (mutually exclusive with repo)
//   - repo          owner/name single-repo scope
//   - api_base      override https://api.github.com
//   - max_blob_bytes per-blob size cap
//   - concurrency   per-repo blob fanout
func scanGitHub(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("github: token is required (set --token or GITHUB_TOKEN)")
	}
	org, repo := cfg["org"], cfg["repo"]
	if org == "" && repo == "" {
		return errors.New("github: either org or repo must be set")
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
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("github: invalid api_base %q", apiBase)
	}
	maxBytes := githubDefaultMaxBlobBytes
	if v := cfg["max_blob_bytes"]; v != "" {
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

	cli := newGitHubClient(apiBase, token)
	repos, err := githubListRepos(ctx, cli, org, repo)
	if err != nil {
		return err
	}
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanGitHubRepo(ctx, cli, r, maxBytes, concurrency, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// per-repo failures are tolerated — keep walking the org.
			continue
		}
	}
	return nil
}

// verifyGitHub hits GET /user. 200 → verified, 401/403 → not verified.
func verifyGitHub(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", githubDefaultAPIBase)
	cli := newGitHubClient(apiBase, secret)
	resp, err := cli.do(ctx, http.MethodGet, "/user", nil)
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
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
}

type githubTreeResp struct {
	SHA       string           `json:"sha"`
	Tree      []githubTreeNode `json:"tree"`
	Truncated bool             `json:"truncated"`
}

type githubTreeNode struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type githubBlobResp struct {
	SHA      string `json:"sha"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
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

func scanGitHubRepo(ctx context.Context, cli *githubClient, repo githubRepoRef, maxBytes int64, concurrency int, emit Emit) error {
	if repo.DefaultBranch == "" {
		path := fmt.Sprintf("/repos/%s/%s", repo.Owner.Login, repo.Name)
		if _, err := cli.getJSON(ctx, path, &repo); err != nil {
			return fmt.Errorf("github: resolve default branch for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
	}
	if repo.DefaultBranch == "" {
		return nil
	}
	var tree githubTreeResp
	treePath := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", repo.Owner.Login, repo.Name, repo.DefaultBranch)
	if _, err := cli.getJSON(ctx, treePath, &tree); err != nil {
		return fmt.Errorf("github: tree %s/%s@%s: %w", repo.Owner.Login, repo.Name, repo.DefaultBranch, err)
	}
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)
	for _, node := range tree.Tree {
		node := node
		if node.Type != "blob" {
			continue
		}
		if node.Size > maxBytes {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return emitGitHubBlob(gctx, cli, repo, node, emit)
		})
	}
	return g.Wait()
}

func emitGitHubBlob(ctx context.Context, cli *githubClient, repo githubRepoRef, node githubTreeNode, emit Emit) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var blob githubBlobResp
	path := fmt.Sprintf("/repos/%s/%s/git/blobs/%s", repo.Owner.Login, repo.Name, node.SHA)
	if _, err := cli.getJSON(ctx, path, &blob); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	var data []byte
	switch blob.Encoding {
	case "base64", "":
		// GitHub wraps base64 with newlines; std encoder rejects whitespace.
		cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(blob.Content)
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil
		}
		data = decoded
	case "utf-8":
		data = []byte(blob.Content)
	default:
		return nil
	}
	visibility := "public"
	if repo.Private {
		visibility = "private"
	} else if repo.Visibility != "" {
		visibility = repo.Visibility
	}
	return emit(data, sources.Metadata{
		GitHub: &sources.GitHubMeta{
			Repository: repo.Owner.Login + "/" + repo.Name,
			File:       node.Path,
			Visibility: visibility,
			Owner:      repo.Owner.Login,
			Repo:       repo.Name,
			Path:       node.Path,
			Sha:        node.SHA,
			Branch:     repo.DefaultBranch,
		},
	})
}

// --- rate-limit-aware HTTP client ---

type githubClient struct {
	base  string
	token string
	http  *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	// testSleep replaces real sleeps in tests. nil in production.
	testSleep func(time.Duration)
}

func newGitHubClient(base, token string) *githubClient {
	if base == "" {
		base = githubDefaultAPIBase
	}
	return &githubClient{
		base:  base,
		token: token,
		http:  &http.Client{Timeout: githubRequestTimeout},
	}
}

func (c *githubClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
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
		c.observeRateLimit(resp)
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

func (c *githubClient) getJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("github: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp, fmt.Errorf("github: decode %s: %w", path, err)
		}
	}
	return resp, nil
}

func (c *githubClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

func (c *githubClient) waitForBucket(ctx context.Context) error {
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
	if c.testSleep != nil {
		c.testSleep(delay)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

func (c *githubClient) observeRateLimit(resp *http.Response) {
	rem := resp.Header.Get("X-RateLimit-Remaining")
	reset := resp.Header.Get("X-RateLimit-Reset")
	if rem == "" || rem != "0" || reset == "" {
		return
	}
	ts, err := strconv.ParseInt(reset, 10, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	c.nextAllowed = time.Unix(ts, 0)
	c.mu.Unlock()
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

func githubBackoff(resp *http.Response, attempt int) time.Duration {
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
	if v := resp.Header.Get("X-RateLimit-Reset"); v != "" {
		if ts, err := strconv.ParseInt(v, 10, 64); err == nil {
			if d := time.Until(time.Unix(ts, 0)); d > 0 {
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
