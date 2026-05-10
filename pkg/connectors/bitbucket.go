// Bitbucket Cloud connector. Single-file Lambda-handler shape.
//
// Surface: workspace or single-repo default-branch files. Issues / PRs /
// pipelines / wikis are out of scope.
//
// Auth: Bearer token (workspace / repository access token) takes priority
// over HTTP Basic (username + app password). Both are accepted; the
// caller picks one.
//
// Pagination: Bitbucket returns absolute "next" URLs in JSON response
// bodies. We follow them verbatim, no cursor arithmetic.

package connectors

import (
	"context"
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
	bitbucketDefaultAPIBase      = "https://api.bitbucket.org/2.0"
	bitbucketDefaultMaxFileBytes = int64(5 * 1024 * 1024)
	bitbucketRequestTimeout      = 60 * time.Second
)

func init() {
	Register("bitbucket", Connector{
		SourceType: sources.SourceBitbucket,
		Scan:       scanBitbucket,
		Verify:     verifyBitbucket,
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
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("bitbucket: invalid api_base %q", apiBase)
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
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanBitbucketRepo(ctx, cli, r, maxBytes, concurrency, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

func verifyBitbucket(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", bitbucketDefaultAPIBase)
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
	Path string `json:"path"`
	Type string `json:"type"`
	Size int64  `json:"size"`
}

type bitbucketPaginatedSrc struct {
	Values []bitbucketSrcEntry `json:"values"`
	Next   string              `json:"next,omitempty"`
}

type bitbucketPaginatedRepos struct {
	Values []bitbucketRepoRef `json:"values"`
	Next   string             `json:"next,omitempty"`
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

func scanBitbucketRepo(ctx context.Context, cli *bitbucketClient, repo bitbucketRepoRef, maxBytes int64, concurrency int, emit Emit) error {
	branch := repo.MainBranch.Name
	if branch == "" {
		return nil
	}
	ws := repo.workspaceSlug()
	slug := repo.Name

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)

	next := fmt.Sprintf("/2.0/repositories/%s/%s/src/%s/?pagelen=100", ws, slug, branch)
	for next != "" {
		if err := gctx.Err(); err != nil {
			return err
		}
		var page bitbucketPaginatedSrc
		if _, err := cli.getJSON(gctx, next, &page); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("bitbucket: src listing %s/%s@%s: %w", ws, slug, branch, err)
		}
		for _, entry := range page.Values {
			entry := entry
			if entry.Type != "commit_file" {
				continue
			}
			if entry.Size > maxBytes {
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			g.Go(func() error {
				defer func() { <-sem }()
				return emitBitbucketFile(gctx, cli, ws, slug, branch, entry, maxBytes, emit)
			})
		}
		next = page.Next
	}
	return g.Wait()
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
	return &bitbucketClient{
		base:        base,
		username:    username,
		appPassword: appPassword,
		bearerToken: bearerToken,
		http:        &http.Client{Timeout: bitbucketRequestTimeout},
	}
}

func (c *bitbucketClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
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
		req.Header.Set("Accept", "application/json")
		c.setAuth(req)
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
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

func (c *bitbucketClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
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
