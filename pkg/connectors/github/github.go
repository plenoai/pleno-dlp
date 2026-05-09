// Package github is the SaaSConnector port for GitHub.com / GitHub Enterprise.
//
// It satisfies sources.Source so the engine drives a GitHub scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Scope for the C1 milestone (issue #74):
//
//   - Auth: Personal Access Token (Bearer). GitHub App installation tokens
//     are advertised in Descriptor.AuthModes for forward compatibility but
//     the JWT-exchange flow is a follow-up.
//   - Source surface: blob fetch from each repo's default branch. Issues,
//     pull-request bodies, gists, and discussions are out of scope; the
//     Config flags (`include_issues`, `include_prs`) are accepted today
//     and ignored, so the JSON shape stays stable when those land.
//   - Verify: GET /user with the supplied PAT. 200 -> verified, 401/403
//     -> not verified, transport errors bubble up (the CLI distinguishes
//     "user said wrong creds" from "we couldn't reach the API").
//
// Concurrency: repos are walked sequentially, blobs within a repo are
// fanned out under a semaphore of size `concurrency` (the engine's worker
// count). This keeps token-bucket pressure bounded while still hiding
// blob-fetch latency. The connector honours ctx.Done() at every send and
// every API call so cancellation propagates promptly.
package github

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// DefaultMaxBlobBytes caps per-blob download size. 5 MiB matches the
// trade-off other tooling (gitleaks, trufflehog) lands on: large enough
// to cover almost every realistic source file, small enough that one
// monorepo full of build artefacts can't hijack the scan budget.
const DefaultMaxBlobBytes int64 = 5 * 1024 * 1024

func init() {
	// Register against both the SaaS connector registry (for `pleno-dlp
	// scan github` and `pleno-dlp verify github` dispatch) and the
	// generic source registry (so existing scan plumbing that asks
	// `sources.New(SourceGitHub)` returns the same implementation).
	// The Connector type satisfies both contracts.
	connectors.Register("github", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceGitHub, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects. The CLI builds it from
// `--token` / `--org` / `--repo` / `--api-base` and a `GITHUB_TOKEN`
// env-var fallback; no auto-discovery from arbitrary disk locations.
type Config struct {
	// Token is a GitHub PAT (`ghp_...` / `github_pat_...`) sent as
	// `Authorization: Bearer <token>`. Required for both scan and
	// verify; the connector does NOT fall back to GITHUB_TOKEN itself
	// (the CLI does that translation).
	Token string `json:"token"`
	// Org scopes the scan to every repo visible under an organisation
	// login. Mutually exclusive with Repo.
	Org string `json:"org,omitempty"`
	// Repo scopes the scan to a single repository in `owner/name` form.
	// Mutually exclusive with Org.
	Repo string `json:"repo,omitempty"`
	// IncludeIssues / IncludePRs are accepted today and ignored — the
	// shape is stable for the follow-up that lands those surfaces.
	IncludeIssues bool `json:"include_issues,omitempty"`
	IncludePRs    bool `json:"include_prs,omitempty"`
	// APIBase overrides the REST root for GitHub Enterprise installations.
	APIBase string `json:"api_base,omitempty"`
	// MaxBlobBytes overrides DefaultMaxBlobBytes; the tree walk skips any
	// blob whose advertised size exceeds this cap.
	MaxBlobBytes int64 `json:"max_blob_bytes,omitempty"`
}

// Connector is the GitHub SaaSConnector. One instance per scan: Init
// validates config, Chunks streams blob bodies, Verify probes /user.
type Connector struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config
	client      *Client
}

// Type returns the wire-stable SourceType for output formatters.
func (c *Connector) Type() sources.SourceType { return sources.SourceGitHub }

// Descriptor returns the static metadata the CLI introspects when
// answering "what does this connector accept?" without instantiating it
// against a token. Capabilities is CapSource | CapVerify for C1; the
// CapRevoke bit lands in D2 (#73).
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "github",
		SourceType: sources.SourceGitHub,
		AuthModes: []connectors.AuthMode{
			connectors.AuthPAT,
			connectors.AuthAppInstallation,
		},
		Capabilities: connectors.CapSource | connectors.CapVerify,
	}
}

// SetAPIBase lets the CLI plumb `--api-base` into a connector that will
// only ever Verify (no Init / Chunks). Init also honours APIBase via
// Config; this setter is a convenience for the verify-only path so the
// CLI doesn't have to fabricate a placeholder Org/Repo just to overwrite
// the api root.
func (c *Connector) SetAPIBase(base string) {
	c.cfg.APIBase = base
}

// Init parses the JSON config, validates auth + scoping, and wires up
// the rate-limit-aware HTTP client. Init MUST be called before Chunks.
// Verify does not require Init when targeting api.github.com — the
// caller can spin a fresh Connector, optionally SetAPIBase, and call
// Verify directly.
func (c *Connector) Init(ctx context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("github: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" {
		return errors.New("github: config.token is required (set --token or GITHUB_TOKEN)")
	}
	if cfg.Org == "" && cfg.Repo == "" {
		return errors.New("github: either config.org or config.repo must be set")
	}
	if cfg.Org != "" && cfg.Repo != "" {
		return errors.New("github: config.org and config.repo are mutually exclusive")
	}
	if cfg.Repo != "" {
		if parts := strings.SplitN(cfg.Repo, "/", 2); len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("github: config.repo must be in owner/name form, got %q", cfg.Repo)
		}
	}
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
	}
	if u, err := url.Parse(cfg.APIBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("github: invalid api_base %q", cfg.APIBase)
	}
	if cfg.MaxBlobBytes <= 0 {
		cfg.MaxBlobBytes = DefaultMaxBlobBytes
	}
	if concurrency <= 0 {
		concurrency = 1
	}
	c.name = name
	c.jobID = jobID
	c.sourceID = sourceID
	c.verify = verifyFlag
	c.concurrency = concurrency
	c.cfg = cfg
	c.client = NewClient(cfg.APIBase, cfg.Token, nil)
	return nil
}

// repoRef captures the subset of GitHub's repo JSON we need: the owner
// login, the repo name, and the default branch we walk for blobs.
type repoRef struct {
	Name  string `json:"name"`
	Owner struct {
		Login string `json:"login"`
	} `json:"owner"`
	DefaultBranch string `json:"default_branch"`
	Private       bool   `json:"private"`
	Visibility    string `json:"visibility"`
}

func (r *repoRef) ownerLogin() string { return r.Owner.Login }

type treeResp struct {
	SHA       string     `json:"sha"`
	Tree      []treeNode `json:"tree"`
	Truncated bool       `json:"truncated"`
}

type treeNode struct {
	Path string `json:"path"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	Size int64  `json:"size"`
}

type blobResp struct {
	SHA      string `json:"sha"`
	Encoding string `json:"encoding"`
	Content  string `json:"content"`
	Size     int64  `json:"size"`
}

// Chunks walks every targeted repo and emits one Chunk per default-branch
// blob. Per-repo failures (404, transient 5xx, permission) are tolerated
// — we keep walking the rest of the org rather than aborting the whole
// scan. The error channel is reserved for context cancellation.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	repos, err := c.listRepos(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Per-repo errors are intentionally swallowed: a single 404 on
		// one repo (deleted between listing and read) must not abort
		// scanning the other 999 in the org. Detector-level error
		// reporting is the right venue for surfacing partial failures
		// — the engine's stats already record per-chunk counts.
		if err := c.scanRepo(ctx, repo, ch); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

// listRepos resolves the configured scope (single repo or whole org)
// into a slice of repoRef. Org enumeration paginates via Link-header
// rel="next" cursors so unrelated `?page=N` arithmetic isn't required.
func (c *Connector) listRepos(ctx context.Context) ([]repoRef, error) {
	if c.cfg.Repo != "" {
		parts := strings.SplitN(c.cfg.Repo, "/", 2)
		path := fmt.Sprintf("/repos/%s/%s", parts[0], parts[1])
		var rr repoRef
		if _, err := c.client.GetJSON(ctx, path, &rr); err != nil {
			return nil, fmt.Errorf("github: get repo %s: %w", c.cfg.Repo, err)
		}
		// Defensive: if the response somehow omitted owner/name (test
		// servers might), fall back to the user-supplied scope.
		if rr.Owner.Login == "" {
			rr.Owner.Login = parts[0]
		}
		if rr.Name == "" {
			rr.Name = parts[1]
		}
		return []repoRef{rr}, nil
	}
	var repos []repoRef
	next := fmt.Sprintf("/orgs/%s/repos?per_page=100&type=all", c.cfg.Org)
	for next != "" {
		var page []repoRef
		resp, err := c.client.GetJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("github: list org %s repos: %w", c.cfg.Org, err)
		}
		repos = append(repos, page...)
		next = parseLinkHeader(resp.Header.Get("Link"))
	}
	return repos, nil
}

// scanRepo resolves the default branch (when missing from the listing
// payload), pulls the recursive tree, and fans out blob fetches.
func (c *Connector) scanRepo(ctx context.Context, repo repoRef, ch chan<- *sources.Chunk) error {
	if repo.DefaultBranch == "" {
		path := fmt.Sprintf("/repos/%s/%s", repo.ownerLogin(), repo.Name)
		if _, err := c.client.GetJSON(ctx, path, &repo); err != nil {
			return fmt.Errorf("github: resolve default branch for %s/%s: %w", repo.ownerLogin(), repo.Name, err)
		}
	}
	if repo.DefaultBranch == "" {
		// Empty repository (no commits yet); nothing to walk.
		return nil
	}
	var tree treeResp
	treePath := fmt.Sprintf("/repos/%s/%s/git/trees/%s?recursive=1", repo.ownerLogin(), repo.Name, repo.DefaultBranch)
	if _, err := c.client.GetJSON(ctx, treePath, &tree); err != nil {
		return fmt.Errorf("github: tree %s/%s@%s: %w", repo.ownerLogin(), repo.Name, repo.DefaultBranch, err)
	}
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.concurrency)
	for _, node := range tree.Tree {
		node := node
		if node.Type != "blob" {
			continue
		}
		if node.Size > c.cfg.MaxBlobBytes {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.emitBlob(gctx, repo, node, ch)
		})
	}
	return g.Wait()
}

// emitBlob fetches the blob body, base64-decodes it, and pushes a Chunk.
// Per-blob fetch errors are intentionally tolerated for the same reason
// per-repo errors are: a single vanished file must not abort the scan.
// Context-cancellation errors are propagated so cancellation is prompt.
func (c *Connector) emitBlob(ctx context.Context, repo repoRef, node treeNode, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var blob blobResp
	path := fmt.Sprintf("/repos/%s/%s/git/blobs/%s", repo.ownerLogin(), repo.Name, node.SHA)
	if _, err := c.client.GetJSON(ctx, path, &blob); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	var data []byte
	switch blob.Encoding {
	case "base64", "":
		// GitHub wraps base64 with newlines. The std encoder rejects
		// embedded whitespace, so strip CR/LF/space first.
		cleaned := strings.NewReplacer("\n", "", "\r", "", " ", "").Replace(blob.Content)
		decoded, err := base64.StdEncoding.DecodeString(cleaned)
		if err != nil {
			return nil
		}
		data = decoded
	case "utf-8":
		data = []byte(blob.Content)
	default:
		// Unknown encoding — skip rather than guess.
		return nil
	}
	visibility := "public"
	if repo.Private {
		visibility = "private"
	} else if repo.Visibility != "" {
		visibility = repo.Visibility
	}
	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceGitHub,
		SourceName: c.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			GitHub: &sources.GitHubMeta{
				// Legacy fields kept populated so existing output
				// formatters render the same shape they always did.
				Repository: repo.ownerLogin() + "/" + repo.Name,
				File:       node.Path,
				Visibility: visibility,
				// Typed fields added for the connector port — clearer
				// dispatch for downstream code that wants the blob sha
				// distinct from a commit sha.
				Owner:  repo.ownerLogin(),
				Repo:   repo.Name,
				Path:   node.Path,
				Sha:    node.SHA,
				Branch: repo.DefaultBranch,
			},
		},
		Verify: c.verify,
	}
	select {
	case ch <- chunk:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Verify implements detectors.Verifier (re-exported as connectors.Verifier).
// 200 -> verified, 401 / 403 -> not verified, transport / unexpected status
// -> error so the CLI can distinguish "credentials wrong" from "we never
// reached the API".
//
// Verify is independent of Init: the CLI can call connectors.New("github"),
// optionally SetAPIBase for a GHES install, and invoke Verify with the
// candidate token. This mirrors detectors.Verifier semantics exactly so
// the verify dispatcher does not branch on connector vs detector.
func (c *Connector) Verify(ctx context.Context, secret string) (bool, error) {
	base := c.cfg.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	cl := NewClient(base, secret, nil)
	resp, err := cl.Do(ctx, http.MethodGet, "/user", nil)
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

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)
