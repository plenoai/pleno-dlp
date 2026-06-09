// GitHub connector. Single-file Lambda-handler shape: auth, fetch, emit.
//
// Surface: org or single-repo default-branch blobs, plus optional issue /
// pull-request comments. GitHub models pull requests as issues, so issue
// comments cover PR conversation comments; pull review comments cover inline
// code-review comments.
//
// Auth: Personal Access Token or GitHub App installation token via
// `Authorization: Bearer <token>` against the public REST API
// (`https://api.github.com`). GitHub Enterprise installs override the base
// via `api_base`.

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
	"net/http"
	"net/url"
	"os"
	"sort"
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
	githubAppJWTLifetime      = 9 * time.Minute
	githubAppRefreshSkew      = 5 * time.Minute
)

func init() {
	Register("github", Connector{
		SourceType:  sources.SourceGitHub,
		Scan:        scanGitHub,
		Verify:      verifyGitHub,
		Fingerprint: fingerprintGitHub,
	})
}

// scanGitHub is the Lambda handler. cfg keys:
//   - token         PAT, sent as Bearer
//   - app_id        GitHub App ID, used with app_installation_id + private key
//   - app_installation_id GitHub App installation ID
//   - app_private_key GitHub App PEM private key
//   - app_private_key_file path to GitHub App PEM private key
//   - org           org login (mutually exclusive with repo)
//   - repo          owner/name single-repo scope
//   - api_base      override https://api.github.com
//   - max_blob_bytes per-blob size cap
//   - concurrency   per-repo blob fanout
//   - include_comments scan issue comments and pull review comments
func scanGitHub(ctx context.Context, cfg Config, emit Emit) error {
	auth, err := newGitHubAuthProvider(cfg)
	if err != nil {
		return err
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

	cli := newGitHubClient(apiBase, auth)
	repos, err := githubListRepos(ctx, cli, org, repo)
	if err != nil {
		return err
	}
	previousState, err := loadGitHubIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &githubIncrementalState{Version: 1, Repos: map[string]githubRepoIncrementalState{}}
	if previousState == nil {
		previousState = &githubIncrementalState{Version: 1, Repos: map[string]githubRepoIncrementalState{}}
	}
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		repoKey := r.Owner.Login + "/" + r.Name
		prevRepo, hasPrevRepo := previousState.Repos[repoKey]
		nextRepo, err := scanGitHubRepoIncremental(ctx, cli, r, prevRepo, hasPrevRepo, maxBytes, concurrency, emit)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// per-repo failures are tolerated — keep walking the org.
			continue
		}
		if parseBool(cfg["include_comments"]) {
			if err := scanGitHubCommentsIncremental(ctx, cli, r, prevRepo, hasPrevRepo, &nextRepo, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		nextState.Repos[repoKey] = nextRepo
	}
	if data, err := json.Marshal(nextState); err == nil {
		cfg[configKeyIncrementalNextState] = string(data)
	}
	return nil
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

type githubIncrementalState struct {
	Version int                                   `json:"version"`
	Repos   map[string]githubRepoIncrementalState `json:"repos"`
}

type githubRepoIncrementalState struct {
	DefaultBranch      string                                   `json:"default_branch,omitempty"`
	Visibility         string                                   `json:"visibility,omitempty"`
	TreeSHA            string                                   `json:"tree_sha,omitempty"`
	TreeTruncated      bool                                     `json:"tree_truncated,omitempty"`
	Blobs              map[string]githubBlobIncrementalState    `json:"blobs,omitempty"`
	IssueComments      map[string]githubCommentIncrementalState `json:"issue_comments,omitempty"`
	PullReviewComments map[string]githubCommentIncrementalState `json:"pull_review_comments,omitempty"`
}

type githubBlobIncrementalState struct {
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type githubCommentIncrementalState struct {
	UpdatedAt string `json:"updated_at"`
	Path      string `json:"path,omitempty"`
	Position  int    `json:"position,omitempty"`
}

func loadGitHubIncrementalState(raw string) (*githubIncrementalState, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var state githubIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("github: parse incremental source state: %w", err)
	}
	if state.Repos == nil {
		state.Repos = map[string]githubRepoIncrementalState{}
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

func scanGitHubRepoIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, maxBytes int64, concurrency int, emit Emit) (githubRepoIncrementalState, error) {
	if repo.DefaultBranch == "" {
		path := fmt.Sprintf("/repos/%s/%s", repo.Owner.Login, repo.Name)
		if _, err := cli.getJSON(ctx, path, &repo); err != nil {
			return githubRepoIncrementalState{}, fmt.Errorf("github: resolve default branch for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
	}
	next := githubRepoIncrementalState{
		DefaultBranch: repo.DefaultBranch,
		Visibility:    repo.Visibility,
		Blobs:         map[string]githubBlobIncrementalState{},
	}
	if repo.DefaultBranch == "" {
		return next, nil
	}
	var tree githubTreeResp
	treePath := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", repo.Owner.Login, repo.Name, repo.DefaultBranch)
	if _, err := cli.getJSON(ctx, treePath, &tree); err != nil {
		return githubRepoIncrementalState{}, fmt.Errorf("github: tree %s/%s@%s: %w", repo.Owner.Login, repo.Name, repo.DefaultBranch, err)
	}
	next.TreeSHA = tree.SHA
	next.TreeTruncated = tree.Truncated

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)
	for _, node := range tree.Tree {
		node := node
		if node.Type != "blob" {
			continue
		}
		next.Blobs[node.Path] = githubBlobIncrementalState{SHA: node.SHA, Size: node.Size}
		if node.Size > maxBytes {
			continue
		}
		if hasPrev && !tree.Truncated && !prev.TreeTruncated && prev.DefaultBranch == repo.DefaultBranch {
			if old, ok := prev.Blobs[node.Path]; ok && old.SHA == node.SHA && old.Size == node.Size {
				continue
			}
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return githubRepoIncrementalState{}, gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return emitGitHubBlob(gctx, cli, repo, node, emit)
		})
	}
	return next, g.Wait()
}

func scanGitHubCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, emit Emit) error {
	if err := scanGitHubIssueCommentsIncremental(ctx, cli, repo, prev, hasPrev, next, emit); err != nil {
		return err
	}
	return scanGitHubPullReviewCommentsIncremental(ctx, cli, repo, prev, hasPrev, next, emit)
}

func scanGitHubIssueCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, emit Emit) error {
	if next.IssueComments == nil {
		next.IssueComments = map[string]githubCommentIncrementalState{}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/issues/comments?per_page=100", repo.Owner.Login, repo.Name)
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

func scanGitHubPullReviewCommentsIncremental(ctx context.Context, cli *githubClient, repo githubRepoRef, prev githubRepoIncrementalState, hasPrev bool, next *githubRepoIncrementalState, emit Emit) error {
	if next.PullReviewComments == nil {
		next.PullReviewComments = map[string]githubCommentIncrementalState{}
	}
	nextPath := fmt.Sprintf("/repos/%s/%s/pulls/comments?per_page=100", repo.Owner.Login, repo.Name)
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

func fingerprintGitHub(ctx context.Context, cfg Config) (string, error) {
	auth, err := newGitHubAuthProvider(cfg)
	if err != nil {
		return "", err
	}
	org, repo := cfg["org"], cfg["repo"]
	if org == "" && repo == "" {
		return "", errors.New("github: either org or repo must be set")
	}
	if org != "" && repo != "" {
		return "", errors.New("github: org and repo are mutually exclusive")
	}
	apiBase := cfg.Get("api_base", githubDefaultAPIBase)
	cli := newGitHubClient(apiBase, auth)
	repos, err := githubListRepos(ctx, cli, org, repo)
	if err != nil {
		return "", err
	}
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].Owner.Login+"/"+repos[i].Name < repos[j].Owner.Login+"/"+repos[j].Name
	})

	h := sha256.New()
	writeFingerprint(h, "github-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, org)
	writeFingerprint(h, repo)
	writeFingerprint(h, cfg.Get("include_comments", "false"))
	for _, r := range repos {
		if err := fingerprintGitHubRepo(ctx, cli, h, r, parseBool(cfg["include_comments"])); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintGitHubRepo(ctx context.Context, cli *githubClient, h hash.Hash, repo githubRepoRef, includeComments bool) error {
	if repo.DefaultBranch == "" {
		path := fmt.Sprintf("/repos/%s/%s", repo.Owner.Login, repo.Name)
		if _, err := cli.getJSON(ctx, path, &repo); err != nil {
			return fmt.Errorf("github: resolve default branch for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
	}
	writeFingerprint(h, repo.Owner.Login+"/"+repo.Name)
	writeFingerprint(h, repo.DefaultBranch)
	writeFingerprint(h, repo.Visibility)
	if repo.DefaultBranch != "" {
		var tree githubTreeResp
		treePath := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", repo.Owner.Login, repo.Name, repo.DefaultBranch)
		if _, err := cli.getJSON(ctx, treePath, &tree); err != nil {
			return fmt.Errorf("github: fingerprint tree %s/%s@%s: %w", repo.Owner.Login, repo.Name, repo.DefaultBranch, err)
		}
		writeFingerprint(h, tree.SHA)
		writeFingerprint(h, strconv.FormatBool(tree.Truncated))
		for _, node := range tree.Tree {
			if node.Type != "blob" {
				continue
			}
			writeFingerprint(h, node.Path)
			writeFingerprint(h, node.SHA)
			writeFingerprint(h, strconv.FormatInt(node.Size, 10))
		}
	}
	if includeComments {
		if err := fingerprintGitHubIssueComments(ctx, cli, h, repo); err != nil {
			return err
		}
		if err := fingerprintGitHubPullReviewComments(ctx, cli, h, repo); err != nil {
			return err
		}
	}
	return nil
}

func fingerprintGitHubIssueComments(ctx context.Context, cli *githubClient, h hash.Hash, repo githubRepoRef) error {
	next := fmt.Sprintf("/repos/%s/%s/issues/comments?per_page=100", repo.Owner.Login, repo.Name)
	for next != "" {
		var page []githubIssueComment
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("github: fingerprint issue comments for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		for _, c := range page {
			writeFingerprint(h, "issue-comment")
			writeFingerprint(h, strconv.FormatInt(c.ID, 10))
			writeFingerprint(h, c.UpdatedAt)
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func fingerprintGitHubPullReviewComments(ctx context.Context, cli *githubClient, h hash.Hash, repo githubRepoRef) error {
	next := fmt.Sprintf("/repos/%s/%s/pulls/comments?per_page=100", repo.Owner.Login, repo.Name)
	for next != "" {
		var page []githubPullReviewComment
		resp, err := cli.getJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("github: fingerprint pull review comments for %s/%s: %w", repo.Owner.Login, repo.Name, err)
		}
		for _, c := range page {
			writeFingerprint(h, "pull-review-comment")
			writeFingerprint(h, strconv.FormatInt(c.ID, 10))
			writeFingerprint(h, c.UpdatedAt)
			writeFingerprint(h, c.Path)
			writeFingerprint(h, strconv.Itoa(c.Position))
		}
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return nil
}

func writeFingerprint(h hash.Hash, s string) {
	_, _ = h.Write([]byte(s))
	_, _ = h.Write([]byte{0})
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
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	if p.token != "" && now.Before(p.expiresAt.Add(-githubAppRefreshSkew)) {
		return p.token, nil
	}
	token, expiresAt, err := p.fetchInstallationToken(ctx, now)
	if err != nil {
		return "", err
	}
	p.token = token
	p.expiresAt = expiresAt
	return p.token, nil
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

	mu          sync.Mutex
	nextAllowed time.Time

	// testSleep replaces real sleeps in tests. nil in production.
	testSleep func(time.Duration)
}

func newGitHubClient(base string, auth githubTokenProvider) *githubClient {
	if base == "" {
		base = githubDefaultAPIBase
	}
	return &githubClient{
		base: base,
		auth: auth,
		http: &http.Client{Timeout: githubRequestTimeout},
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
		if c.auth != nil {
			token, err := c.auth.Token(ctx)
			if err != nil {
				return nil, err
			}
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
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
