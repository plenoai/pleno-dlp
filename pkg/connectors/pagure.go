package connectors

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const pagureDefaultMaxCommentBytes = int64(1024 * 1024)

func init() {
	Register("pagure", Connector{
		SourceType: sources.SourcePagure,
		Scan:       scanPagure,
	})
}

func scanPagure(ctx context.Context, cfg Config, emit Emit) error {
	repo := strings.Trim(cfg["repo"], "/")
	if repo == "" {
		return fmt.Errorf("pagure: --repo is required")
	}
	apiBase := cfg.Get("api_base", "https://pagure.io/api/0")
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("pagure: invalid api_base %q", apiBase)
	}
	maxBytes := pagureDefaultMaxCommentBytes
	if v := cfg["max_comment_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}

	cli := newPagureClient(apiBase, cfg["token"])
	if err := scanPagureIssues(ctx, cli, repo, maxBytes, emit); err != nil {
		return err
	}
	return scanPagurePullRequests(ctx, cli, repo, maxBytes, emit)
}

type pagureIssuePage struct {
	Issues     []pagureIssue    `json:"issues"`
	Pagination pagurePagination `json:"pagination"`
}

type pagurePRPage struct {
	Requests   []pagurePullRequest `json:"requests"`
	Pagination pagurePagination    `json:"pagination"`
}

type pagurePagination struct {
	Next string `json:"next"`
}

type pagureIssue struct {
	ID       int64           `json:"id"`
	Content  string          `json:"content"`
	FullURL  string          `json:"full_url"`
	Comments []pagureComment `json:"comments"`
}

type pagurePullRequest struct {
	ID             int64           `json:"id"`
	InitialComment string          `json:"initial_comment"`
	FullURL        string          `json:"full_url"`
	Comments       []pagureComment `json:"comments"`
}

type pagureComment struct {
	ID      int64  `json:"id"`
	Comment string `json:"comment"`
}

func scanPagureIssues(ctx context.Context, cli *pagureClient, repo string, maxBytes int64, emit Emit) error {
	next := "/" + escapePathSegments(repo) + "/issues?per_page=100"
	for next != "" {
		var page pagureIssuePage
		if err := cli.getJSON(ctx, next, &page); err != nil {
			return fmt.Errorf("pagure: list issues for %s: %w", repo, err)
		}
		for _, issue := range page.Issues {
			if err := emitPagurePart(issue.Content, maxBytes, sources.ForgeMeta{
				Provider:   "pagure",
				Repository: repo,
				File:       fmt.Sprintf("issue:%d:description", issue.ID),
				Line:       1,
			}, emit); err != nil {
				return err
			}
			for _, comment := range issue.Comments {
				if err := emitPagurePart(comment.Comment, maxBytes, sources.ForgeMeta{
					Provider:   "pagure",
					Repository: repo,
					File:       fmt.Sprintf("issue:%d:comment:%d", issue.ID, comment.ID),
					Line:       1,
				}, emit); err != nil {
					return err
				}
			}
		}
		next = page.Pagination.Next
	}
	return nil
}

func scanPagurePullRequests(ctx context.Context, cli *pagureClient, repo string, maxBytes int64, emit Emit) error {
	next := "/" + escapePathSegments(repo) + "/pull-requests?per_page=100"
	for next != "" {
		var page pagurePRPage
		if err := cli.getJSON(ctx, next, &page); err != nil {
			return fmt.Errorf("pagure: list pull requests for %s: %w", repo, err)
		}
		for _, pr := range page.Requests {
			if err := emitPagurePart(pr.InitialComment, maxBytes, sources.ForgeMeta{
				Provider:   "pagure",
				Repository: repo,
				File:       fmt.Sprintf("pull-request:%d:description", pr.ID),
				Line:       1,
			}, emit); err != nil {
				return err
			}
			for _, comment := range pr.Comments {
				if err := emitPagurePart(comment.Comment, maxBytes, sources.ForgeMeta{
					Provider:   "pagure",
					Repository: repo,
					File:       fmt.Sprintf("pull-request:%d:comment:%d", pr.ID, comment.ID),
					Line:       1,
				}, emit); err != nil {
					return err
				}
			}
		}
		next = page.Pagination.Next
	}
	return nil
}

func emitPagurePart(text string, maxBytes int64, meta sources.ForgeMeta, emit Emit) error {
	text = strings.TrimSpace(text)
	if text == "" || int64(len(text)) > maxBytes {
		return nil
	}
	return emit([]byte(text), sources.Metadata{Forge: &meta})
}

type pagureClient struct {
	base  string
	token string
	http  *http.Client
}

func newPagureClient(base, token string) *pagureClient {
	return &pagureClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *pagureClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "token "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *pagureClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if strings.HasPrefix(p, "/") {
		return c.base + p
	}
	return c.base + "/" + p
}

func escapePathSegments(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
