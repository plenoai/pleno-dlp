package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const onedevDefaultMaxCommentBytes = int64(1024 * 1024)

func init() {
	Register("onedev", Connector{
		SourceType:  sources.SourceOneDev,
		Scan:        scanOneDev,
		Fingerprint: fingerprintOneDev,
	})
}

func scanOneDev(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return fmt.Errorf("onedev: token is required")
	}
	apiBase := cfg["api_base"]
	if apiBase == "" {
		return fmt.Errorf("onedev: --api-base is required")
	}
	if u, err := url.Parse(apiBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("onedev: invalid api_base %q", apiBase)
	}
	projectID := cfg.Get("project_id", cfg["repo"])
	if projectID == "" {
		return fmt.Errorf("onedev: --project-id or --repo is required")
	}
	maxBytes := onedevDefaultMaxCommentBytes
	if v := cfg["max_comment_bytes"]; v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			maxBytes = n
		}
	}

	cli := newOneDevClient(apiBase, token)
	previousState, err := loadForgeIncrementalState(cfg[configKeyIncrementalPreviousState], "onedev")
	if err != nil {
		return err
	}
	nextState := &forgeIncrementalState{Version: 1, Objects: map[string]forgeObjectIncrementalState{}}
	if previousState == nil {
		previousState = &forgeIncrementalState{Version: 1, Objects: map[string]forgeObjectIncrementalState{}}
	}
	scanState := forgeScanState{previous: previousState, next: nextState}
	if err := scanOneDevIssues(ctx, cli, projectID, maxBytes, &scanState, emit); err != nil {
		return err
	}
	if err := scanOneDevPulls(ctx, cli, projectID, maxBytes, &scanState, emit); err != nil {
		return err
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("onedev: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return nil
}

func fingerprintOneDev(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", fmt.Errorf("onedev: token is required")
	}
	apiBase := cfg["api_base"]
	if apiBase == "" {
		return "", fmt.Errorf("onedev: --api-base is required")
	}
	projectID := cfg.Get("project_id", cfg["repo"])
	if projectID == "" {
		return "", fmt.Errorf("onedev: --project-id or --repo is required")
	}
	cli := newOneDevClient(apiBase, token)
	h := sha256.New()
	writeFingerprint(h, "onedev-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, projectID)
	if err := fingerprintOneDevIssues(ctx, h, cli, projectID); err != nil {
		return "", err
	}
	if err := fingerprintOneDevPulls(ctx, h, cli, projectID); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type oneDevProjectRef struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
	Name string `json:"name"`
}

type oneDevIssue struct {
	ID          int64            `json:"id"`
	Number      int64            `json:"number"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Project     oneDevProjectRef `json:"project"`
}

type oneDevPull struct {
	ID          int64            `json:"id"`
	Number      int64            `json:"number"`
	Title       string           `json:"title"`
	Description string           `json:"description"`
	Project     oneDevProjectRef `json:"project"`
}

type oneDevComment struct {
	ID      int64            `json:"id"`
	Content string           `json:"content"`
	Project oneDevProjectRef `json:"project"`
}

func scanOneDevIssues(ctx context.Context, cli *oneDevClient, projectID string, maxBytes int64, state *forgeScanState, emit Emit) error {
	for offset := 0; ; offset += 100 {
		var issues []oneDevIssue
		if err := cli.getJSON(ctx, fmt.Sprintf("/issues?offset=%d&count=100", offset), &issues); err != nil {
			return fmt.Errorf("onedev: list issues: %w", err)
		}
		if len(issues) == 0 {
			return nil
		}
		for _, issue := range issues {
			if !oneDevProjectMatches(issue.Project, projectID) {
				continue
			}
			repo := oneDevRepoName(issue.Project, projectID)
			if err := emitOneDevPart(issue.Description, maxBytes, state, sources.ForgeMeta{
				Provider:   "onedev",
				Repository: repo,
				File:       fmt.Sprintf("issue:%d:description", issueIDForPath(issue)),
				Line:       1,
			}, emit); err != nil {
				return err
			}
			var comments []oneDevComment
			if err := cli.getJSON(ctx, fmt.Sprintf("/issues/%d/comments", issue.ID), &comments); err != nil {
				return fmt.Errorf("onedev: list issue comments for %d: %w", issue.ID, err)
			}
			for _, comment := range comments {
				if err := emitOneDevPart(comment.Content, maxBytes, state, sources.ForgeMeta{
					Provider:   "onedev",
					Repository: repo,
					File:       fmt.Sprintf("issue:%d:comment:%d", issueIDForPath(issue), comment.ID),
					Line:       1,
				}, emit); err != nil {
					return err
				}
			}
		}
	}
}

func scanOneDevPulls(ctx context.Context, cli *oneDevClient, projectID string, maxBytes int64, state *forgeScanState, emit Emit) error {
	for offset := 0; ; offset += 100 {
		var pulls []oneDevPull
		if err := cli.getJSON(ctx, fmt.Sprintf("/pulls?offset=%d&count=100", offset), &pulls); err != nil {
			return fmt.Errorf("onedev: list pull requests: %w", err)
		}
		if len(pulls) == 0 {
			return nil
		}
		for _, pr := range pulls {
			if !oneDevProjectMatches(pr.Project, projectID) {
				continue
			}
			repo := oneDevRepoName(pr.Project, projectID)
			if err := emitOneDevPart(pr.Description, maxBytes, state, sources.ForgeMeta{
				Provider:   "onedev",
				Repository: repo,
				File:       fmt.Sprintf("pull-request:%d:description", pullIDForPath(pr)),
				Line:       1,
			}, emit); err != nil {
				return err
			}
			var comments []oneDevComment
			if err := cli.getJSON(ctx, fmt.Sprintf("/pulls/%d/comments", pr.ID), &comments); err != nil {
				return fmt.Errorf("onedev: list pull request comments for %d: %w", pr.ID, err)
			}
			for _, comment := range comments {
				if err := emitOneDevPart(comment.Content, maxBytes, state, sources.ForgeMeta{
					Provider:   "onedev",
					Repository: repo,
					File:       fmt.Sprintf("pull-request:%d:comment:%d", pullIDForPath(pr), comment.ID),
					Line:       1,
				}, emit); err != nil {
					return err
				}
			}
		}
	}
}

func fingerprintOneDevIssues(ctx context.Context, h hash.Hash, cli *oneDevClient, projectID string) error {
	for offset := 0; ; offset += 100 {
		var issues []oneDevIssue
		if err := cli.getJSON(ctx, fmt.Sprintf("/issues?offset=%d&count=100", offset), &issues); err != nil {
			return fmt.Errorf("onedev: list issues: %w", err)
		}
		if len(issues) == 0 {
			return nil
		}
		for _, issue := range issues {
			if !oneDevProjectMatches(issue.Project, projectID) {
				continue
			}
			writeFingerprint(h, fmt.Sprintf("issue:%d:description", issueIDForPath(issue)))
			writeFingerprint(h, issue.Description)
			var comments []oneDevComment
			if err := cli.getJSON(ctx, fmt.Sprintf("/issues/%d/comments", issue.ID), &comments); err != nil {
				return fmt.Errorf("onedev: list issue comments for %d: %w", issue.ID, err)
			}
			for _, comment := range comments {
				writeFingerprint(h, fmt.Sprintf("issue:%d:comment:%d", issueIDForPath(issue), comment.ID))
				writeFingerprint(h, comment.Content)
			}
		}
	}
}

func fingerprintOneDevPulls(ctx context.Context, h hash.Hash, cli *oneDevClient, projectID string) error {
	for offset := 0; ; offset += 100 {
		var pulls []oneDevPull
		if err := cli.getJSON(ctx, fmt.Sprintf("/pulls?offset=%d&count=100", offset), &pulls); err != nil {
			return fmt.Errorf("onedev: list pull requests: %w", err)
		}
		if len(pulls) == 0 {
			return nil
		}
		for _, pr := range pulls {
			if !oneDevProjectMatches(pr.Project, projectID) {
				continue
			}
			writeFingerprint(h, fmt.Sprintf("pull-request:%d:description", pullIDForPath(pr)))
			writeFingerprint(h, pr.Description)
			var comments []oneDevComment
			if err := cli.getJSON(ctx, fmt.Sprintf("/pulls/%d/comments", pr.ID), &comments); err != nil {
				return fmt.Errorf("onedev: list pull request comments for %d: %w", pr.ID, err)
			}
			for _, comment := range comments {
				writeFingerprint(h, fmt.Sprintf("pull-request:%d:comment:%d", pullIDForPath(pr), comment.ID))
				writeFingerprint(h, comment.Content)
			}
		}
	}
}

func oneDevProjectMatches(project oneDevProjectRef, want string) bool {
	if strconv.FormatInt(project.ID, 10) == want {
		return true
	}
	return project.Path == want || project.Name == want
}

func oneDevRepoName(project oneDevProjectRef, fallback string) string {
	if project.Path != "" {
		return project.Path
	}
	if project.Name != "" {
		return project.Name
	}
	return fallback
}

func issueIDForPath(issue oneDevIssue) int64 {
	if issue.Number != 0 {
		return issue.Number
	}
	return issue.ID
}

func pullIDForPath(pr oneDevPull) int64 {
	if pr.Number != 0 {
		return pr.Number
	}
	return pr.ID
}

func emitOneDevPart(text string, maxBytes int64, state *forgeScanState, meta sources.ForgeMeta, emit Emit) error {
	text = strings.TrimSpace(text)
	if text == "" || int64(len(text)) > maxBytes {
		return nil
	}
	return emitForgePartIncremental(text, state, meta, emit)
}

type oneDevClient struct {
	base  string
	token string
	http  *http.Client
}

func newOneDevClient(base, token string) *oneDevClient {
	return &oneDevClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

func (c *oneDevClient) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url(path), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
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

func (c *oneDevClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if strings.HasPrefix(p, "/") {
		return c.base + p
	}
	return c.base + "/" + p
}
