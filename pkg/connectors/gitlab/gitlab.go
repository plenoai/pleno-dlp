// Package gitlab is the SaaSConnector port for GitLab.com / self-hosted GitLab.
//
// It satisfies sources.Source so the engine drives a GitLab scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Scope for the C2 milestone (issue #75):
//
//   - Auth: PAT (glpat-...) via PRIVATE-TOKEN header. Bearer for OAuth
//     tokens. Header chosen by token shape: glpat- prefix → PRIVATE-TOKEN,
//     others → Authorization: Bearer.
//   - Source surface: blob fetch from each project's default branch. Issues,
//     MR bodies, snippets, and wiki are out of scope.
//   - Verify: GET /user with the supplied token. 200 → verified, 401 → not
//     verified, transport errors bubble up.
//
// Concurrency: projects are walked sequentially, blobs within a project are
// fanned out under a semaphore of size concurrency. The connector honours
// ctx.Done() at every send and every API call so cancellation propagates.
package gitlab

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/connectors/_paginate"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// DefaultMaxBlobBytes caps per-blob download size. 5 MiB matches the
// trade-off other tooling (gitleaks, trufflehog) lands on.
const DefaultMaxBlobBytes int64 = 5 * 1024 * 1024

// DefaultAPIBase is the public gitlab.com REST root. Self-hosted GitLab
// callers override this via Config.APIBase / --api-base.
const DefaultAPIBase = "https://gitlab.com/api/v4"

func init() {
	connectors.Register("gitlab", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceGitLab, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects. The CLI builds it from
// --token / --group / --project / --api-base and a GITLAB_TOKEN
// env-var fallback.
type Config struct {
	// Token is a GitLab PAT (glpat-...) or OAuth token. When the token
	// starts with glpat-, it is sent as PRIVATE-TOKEN; otherwise as
	// Authorization: Bearer.
	Token string `json:"token"`
	// Group scopes the scan to every project visible under a group path.
	// Mutually exclusive with Project.
	Group string `json:"group,omitempty"`
	// Project scopes the scan to a single project in namespace/name form.
	// Mutually exclusive with Group. Namespace may contain slashes for
	// subgroups (e.g. engineering/backend/api).
	Project string `json:"project,omitempty"`
	// APIBase overrides the REST root for self-hosted GitLab installations.
	APIBase string `json:"api_base,omitempty"`
	// MaxBlobBytes overrides DefaultMaxBlobBytes; the tree walk skips any
	// blob whose advertised size exceeds this cap.
	MaxBlobBytes int64 `json:"max_blob_bytes,omitempty"`
}

// Connector is the GitLab SaaSConnector. One instance per scan: Init
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
func (c *Connector) Type() sources.SourceType { return sources.SourceGitLab }

// Descriptor returns the static metadata the CLI introspects when
// answering "what does this connector accept?" without instantiating it
// against a token.
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "gitlab",
		SourceType: sources.SourceGitLab,
		AuthModes: []connectors.AuthMode{
			connectors.AuthPAT,
			connectors.AuthBearer,
			connectors.AuthOAuth,
		},
		Capabilities: connectors.CapSource | connectors.CapVerify,
	}
}

// SetAPIBase lets the CLI plumb --api-base into a connector that will
// only ever Verify (no Init / Chunks). Init also honours APIBase via
// Config; this setter is a convenience for the verify-only path.
func (c *Connector) SetAPIBase(base string) {
	c.cfg.APIBase = base
}

// Init parses the JSON config, validates auth + scoping, and wires up
// the rate-limit-aware HTTP client. Init MUST be called before Chunks.
func (c *Connector) Init(ctx context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("gitlab: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" {
		return errors.New("gitlab: config.token is required (set --token or GITLAB_TOKEN)")
	}
	if cfg.Group == "" && cfg.Project == "" {
		return errors.New("gitlab: either config.group or config.project must be set")
	}
	if cfg.Group != "" && cfg.Project != "" {
		return errors.New("gitlab: config.group and config.project are mutually exclusive")
	}
	if cfg.Project != "" {
		parts := strings.SplitN(cfg.Project, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("gitlab: config.project must be in namespace/name form, got %q", cfg.Project)
		}
	}
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
	}
	if u, err := url.Parse(cfg.APIBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("gitlab: invalid api_base %q", cfg.APIBase)
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

// projectRef captures the subset of GitLab project JSON we need.
type projectRef struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	PathWithNS    string `json:"path_with_namespace"`
	DefaultBranch string `json:"default_branch"`
}

// treeEntry is a single node in GitLab repository tree response.
type treeEntry struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"` // "blob" or "tree"
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// Chunks walks every targeted project and emits one Chunk per default-branch
// blob. Per-project failures (404, transient 5xx, permission) are tolerated —
// we keep walking the rest of the group rather than aborting the whole scan.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	projects, err := c.listProjects(ctx)
	if err != nil {
		return err
	}
	for _, proj := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.scanProject(ctx, proj, ch); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

// listProjects resolves the configured scope (single project or whole group)
// into a slice of projectRef. Group enumeration paginates via Link-header
// rel="next" cursors. Keyset pagination is preferred; offset is the fallback.
func (c *Connector) listProjects(ctx context.Context) ([]projectRef, error) {
	if c.cfg.Project != "" {
		encoded := url.PathEscape(c.cfg.Project)
		path := fmt.Sprintf("/projects/%s", encoded)
		var proj projectRef
		if _, err := c.client.GetJSON(ctx, path, &proj); err != nil {
			return nil, fmt.Errorf("gitlab: get project %s: %w", c.cfg.Project, err)
		}
		return []projectRef{proj}, nil
	}
	// Group enumeration: keyset pagination (GitLab recommended for large
	// groups). Keyset pagination returns Link headers just like offset
	// pagination, so the cursor-following loop is the same.
	var projects []projectRef
	next := fmt.Sprintf("/groups/%s/projects?include_subgroups=true&per_page=100&pagination=keyset&order_by=id",
		url.PathEscape(c.cfg.Group))
	for next != "" {
		var page []projectRef
		resp, err := c.client.GetJSON(ctx, next, &page)
		if err != nil {
			return nil, fmt.Errorf("gitlab: list group %s projects: %w", c.cfg.Group, err)
		}
		projects = append(projects, page...)
		next = _paginate.ParseLinkHeader(resp.Header.Get("Link"))
	}
	return projects, nil
}

// scanProject resolves the default branch, pulls the recursive tree,
// and fans out blob fetches.
func (c *Connector) scanProject(ctx context.Context, proj projectRef, ch chan<- *sources.Chunk) error {
	// Resolve default branch when missing from listing payload.
	if proj.DefaultBranch == "" {
		path := fmt.Sprintf("/projects/%d", proj.ID)
		if _, err := c.client.GetJSON(ctx, path, &proj); err != nil {
			return fmt.Errorf("gitlab: resolve default branch for project %d: %w", proj.ID, err)
		}
	}
	if proj.DefaultBranch == "" {
		// Empty project (no commits yet); nothing to walk.
		return nil
	}

	// Walk the recursive tree. GitLab tree API is paginated (per_page=100
	// max). Follow Link headers until no next page.
	var entries []treeEntry
	next := fmt.Sprintf("/projects/%d/repository/tree?recursive=true&per_page=100&ref=%s",
		proj.ID, url.QueryEscape(proj.DefaultBranch))
	for next != "" {
		var page []treeEntry
		resp, err := c.client.GetJSON(ctx, next, &page)
		if err != nil {
			return fmt.Errorf("gitlab: tree project %d@%s: %w", proj.ID, proj.DefaultBranch, err)
		}
		entries = append(entries, page...)
		next = _paginate.ParseLinkHeader(resp.Header.Get("Link"))
	}

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.concurrency)
	for _, entry := range entries {
		entry := entry
		if entry.Type != "blob" {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-gctx.Done():
			return gctx.Err()
		}
		g.Go(func() error {
			defer func() { <-sem }()
			return c.emitBlob(gctx, proj, entry, ch)
		})
	}
	return g.Wait()
}

// emitBlob fetches the raw file content and pushes a Chunk. GitLab's
// repository/files/raw endpoint returns bytes directly (no base64 encoding),
// unlike GitHub's blob API.
func (c *Connector) emitBlob(ctx context.Context, proj projectRef, entry treeEntry, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	path := fmt.Sprintf("/projects/%d/repository/files/%s/raw?ref=%s",
		proj.ID, url.PathEscape(entry.Path), url.QueryEscape(proj.DefaultBranch))
	resp, err := c.client.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}

	// Read up to MaxBlobBytes + 1; if the file is larger, skip it.
	limited := io.LimitReader(resp.Body, c.cfg.MaxBlobBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil
	}
	if int64(len(data)) > c.cfg.MaxBlobBytes {
		// Oversize — skip
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceGitLab,
		SourceName: c.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			GitLab: &sources.GitLabMeta{
				ProjectID: proj.ID,
				Path:      entry.Path,
				Sha:       entry.ID,
				Branch:    proj.DefaultBranch,
				Group:     c.cfg.Group,
				Project:   proj.PathWithNS,
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
// 200 → verified, 401 → not verified, transport / unexpected status → error.
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
		return false, fmt.Errorf("gitlab: verify unexpected status %s", resp.Status)
	}
}

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)
