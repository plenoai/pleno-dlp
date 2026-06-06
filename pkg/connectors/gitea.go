// Gitea-compatible forge connectors.
//
// Surface: single repository issue comments. Forgejo and
// Codeberg expose the Gitea API shape; Gogs follows the same broad v1 shape.
// GitBucket's API v3 is GitHub-like enough for the repository comments
// endpoint. Repository blobs are intentionally out of scope here because
// local/remote Git scanning already covers Git content, while API-only
// comments do not.
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

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	giteaDefaultMaxCommentBytes = int64(1024 * 1024)
	giteaRequestTimeout         = 60 * time.Second
)

type giteaProvider struct {
	name    string
	typ     sources.SourceType
	env     string
	apiBase string
}

var giteaProviders = []giteaProvider{
	{name: "forgejo", typ: sources.SourceForgejo, env: "FORGEJO_TOKEN"},
	{name: "gitea", typ: sources.SourceGitea, env: "GITEA_TOKEN"},
	{name: "gogs", typ: sources.SourceGogs, env: "GOGS_TOKEN"},
	{name: "gitbucket", typ: sources.SourceGitbucket, env: "GITBUCKET_TOKEN"},
	{name: "codeberg", typ: sources.SourceCodeberg, env: "CODEBERG_TOKEN", apiBase: "https://codeberg.org/api/v1"},
}

func init() {
	for _, p := range giteaProviders {
		p := p
		Register(p.name, Connector{
			SourceType: p.typ,
			Scan: func(ctx context.Context, cfg Config, emit Emit) error {
				return scanGiteaCompatible(ctx, p, cfg, emit)
			},
			Verify: func(ctx context.Context, cfg Config, secret string) (bool, error) {
				return verifyGiteaCompatible(ctx, p, cfg, secret)
			},
		})
	}
}

func scanGiteaCompatible(ctx context.Context, provider giteaProvider, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return fmt.Errorf("%s: token is required", provider.name)
	}
	repo := cfg["repo"]
	owner, name, ok := splitOwnerRepo(repo)
	if !ok {
		return fmt.Errorf("%s: repo must be in owner/name form, got %q", provider.name, repo)
	}
	apiBase := cfg.Get("api_base", provider.apiBase)
	if apiBase == "" {
		return fmt.Errorf("%s: --api-base is required", provider.name)
	}
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s: invalid api_base %q", provider.name, apiBase)
	}
	maxBytes := giteaDefaultMaxCommentBytes
	if v := cfg["max_comment_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}

	cli := newGiteaClient(apiBase, token)
	return scanGiteaIssueComments(ctx, provider, cli, owner, name, maxBytes, emit)
}

func verifyGiteaCompatible(ctx context.Context, provider giteaProvider, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", provider.apiBase)
	if apiBase == "" {
		return false, fmt.Errorf("%s: api_base is required for verify", provider.name)
	}
	cli := newGiteaClient(apiBase, secret)
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
		return false, fmt.Errorf("%s: verify unexpected status %s", provider.name, resp.Status)
	}
}

type giteaComment struct {
	ID       int64  `json:"id"`
	Body     string `json:"body"`
	HTMLURL  string `json:"html_url"`
	IssueURL string `json:"issue_url"`
}

func scanGiteaIssueComments(ctx context.Context, provider giteaProvider, cli *giteaClient, owner, repo string, maxBytes int64, emit Emit) error {
	next := fmt.Sprintf("/repos/%s/%s/issues/comments?limit=100", url.PathEscape(owner), url.PathEscape(repo))
	for next != "" {
		var page []giteaComment
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("%s: list issue comments for %s/%s: %w", provider.name, owner, repo, err)
		}
		for _, c := range page {
			body := strings.TrimSpace(c.Body)
			if body == "" || int64(len(body)) > maxBytes {
				continue
			}
			if err := emit([]byte(body), sources.Metadata{
				Forge: &sources.ForgeMeta{
					Provider:   provider.name,
					Repository: owner + "/" + repo,
					File:       fmt.Sprintf("issue-comment:%d", c.ID),
					Line:       1,
				},
			}); err != nil {
				return err
			}
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

type giteaClient struct {
	base  string
	token string
	http  *http.Client

	mu          sync.Mutex
	nextAllowed time.Time
	testSleep   func(time.Duration)
}

func newGiteaClient(base, token string) *giteaClient {
	return &giteaClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: giteaRequestTimeout},
	}
}

func (c *giteaClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
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
		if c.token != "" {
			req.Header.Set("Authorization", "token "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, err
			}
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := time.Duration(attempt+1) * time.Second
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
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
		lastErr = errors.New("exhausted retries against rate limit")
	}
	return nil, lastErr
}

func (c *giteaClient) getJSON(ctx context.Context, path string, out any) (*http.Response, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return resp, fmt.Errorf("GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return resp, fmt.Errorf("decode %s: %w", path, err)
	}
	return resp, nil
}

func (c *giteaClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if strings.HasPrefix(p, "/") {
		return c.base + p
	}
	return c.base + "/" + p
}

func (c *giteaClient) waitForBucket(ctx context.Context) error {
	c.mu.Lock()
	wait := time.Until(c.nextAllowed)
	c.mu.Unlock()
	if wait <= 0 {
		return ctx.Err()
	}
	if c.testSleep != nil {
		c.testSleep(wait)
		return ctx.Err()
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(wait):
		return nil
	}
}

func splitOwnerRepo(repo string) (string, string, bool) {
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}
