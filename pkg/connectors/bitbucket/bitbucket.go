// Package bitbucket is the SaaSConnector port for Bitbucket Cloud.
//
// It satisfies sources.Source so the engine drives a Bitbucket scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Scope for the C1 milestone (issue #76):
//
//   - Auth: App password (HTTP Basic with username + app_password) and
//     Bearer token (workspace / repository access token).
//   - Source surface: raw file fetch from each repo's default branch via the
//     /src/{branch}/ directory listing API. Issues, pull requests, pipelines,
//     and wikis are out of scope.
//   - Verify: GET /2.0/user with the supplied credentials. 200 → verified,
//     401 → not verified, transport errors bubble up.
//
// Concurrency: repos are walked sequentially, files within a repo are
// fanned out under a semaphore of size `concurrency`. The connector honours
// ctx.Done() at every send and every API call so cancellation propagates promptly.
package bitbucket

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
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// DefaultAPIBase is the public Bitbucket Cloud REST root.
const DefaultAPIBase = "https://api.bitbucket.org/2.0"

// DefaultMaxFileBytes caps per-file download size. 5 MiB matches the
// trade-off other tooling (gitleaks, trufflehog) lands on.
const DefaultMaxFileBytes int64 = 5 * 1024 * 1024

func init() {
	connectors.Register("bitbucket", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceBitbucket, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects. The CLI builds it from
// --username / --app-password / --token / --workspace / --repo / --api-base
// and a BITBUCKET_APP_PASSWORD env-var fallback.
type Config struct {
	// Username for app-password auth (HTTP Basic). Required when using
	// AppPassword; ignored when Token is set.
	Username string `json:"username,omitempty"`
	// AppPassword is the Bitbucket app password sent as HTTP Basic password.
	// Mutually exclusive with Token.
	AppPassword string `json:"app_password,omitempty"`
	// Token is a workspace or repository access token sent as Bearer.
	// Mutually exclusive with AppPassword.
	Token string `json:"token,omitempty"`
	// Workspace scopes the scan to every repo visible under a Bitbucket
	// workspace. When empty, Repo must be set.
	Workspace string `json:"workspace,omitempty"`
	// Repo scopes the scan to a single repository in "workspace/slug" form.
	// Mutually exclusive with Workspace (used alone).
	Repo string `json:"repo,omitempty"`
	// APIBase overrides the REST root. Defaults to DefaultAPIBase.
	APIBase string `json:"api_base,omitempty"`
	// MaxFileBytes overrides DefaultMaxFileBytes; the src tree walk skips
	// any file whose advertised size exceeds this cap.
	MaxFileBytes int64 `json:"max_file_bytes,omitempty"`
}

// Connector is the Bitbucket Cloud SaaSConnector. One instance per scan:
// Init validates config, Chunks streams file bodies, Verify probes /user.
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
func (c *Connector) Type() sources.SourceType { return sources.SourceBitbucket }

// Descriptor returns the static metadata the CLI introspects when answering
// "what does this connector accept?" without instantiating against a token.
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "bitbucket",
		SourceType: sources.SourceBitbucket,
		AuthModes: []connectors.AuthMode{
			connectors.AuthBasic,
			connectors.AuthBearer,
		},
		Capabilities: connectors.CapSource | connectors.CapVerify,
	}
}

// SetAPIBase lets the CLI plumb --api-base into a connector that will only
// ever Verify (no Init / Chunks). Mirrors the GitHub connector pattern.
func (c *Connector) SetAPIBase(base string) {
	c.cfg.APIBase = base
}

// Init parses the JSON config, validates auth + scoping, and wires up the
// rate-limit-aware HTTP client. Init MUST be called before Chunks.
func (c *Connector) Init(ctx context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("bitbucket: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" && cfg.AppPassword == "" {
		return errors.New("bitbucket: config.token or config.app_password is required (set --token / --app-password or BITBUCKET_APP_PASSWORD)")
	}
	if cfg.Token != "" && cfg.AppPassword != "" {
		return errors.New("bitbucket: config.token and config.app_password are mutually exclusive")
	}
	if cfg.AppPassword != "" && cfg.Username == "" {
		return errors.New("bitbucket: config.username is required when using app_password auth")
	}
	if cfg.Workspace == "" && cfg.Repo == "" {
		return errors.New("bitbucket: config.workspace or config.repo must be set")
	}
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
	}
	if u, err := url.Parse(cfg.APIBase); err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("bitbucket: invalid api_base %q", cfg.APIBase)
	}
	if cfg.MaxFileBytes <= 0 {
		cfg.MaxFileBytes = DefaultMaxFileBytes
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
	c.client = NewClient(cfg.APIBase, cfg.Username, cfg.AppPassword, cfg.Token, nil)
	return nil
}

// repoRef captures the subset of Bitbucket's repo JSON we need.
type repoRef struct {
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

func (r *repoRef) workspaceSlug() string {
	if r.Workspace.Slug != "" {
		return r.Workspace.Slug
	}
	if i := strings.IndexByte(r.FullName, '/'); i > 0 {
		return r.FullName[:i]
	}
	return ""
}

// srcEntry is a single entry in the /src/{branch}/ directory listing.
type srcEntry struct {
	Path string `json:"path"`
	Type string `json:"type"` // "commit_file" or "commit_directory"
	Size int64  `json:"size"`
}

// paginatedSrc is the Bitbucket response shape for directory listings.
type paginatedSrc struct {
	Values []srcEntry `json:"values"`
	Next   string     `json:"next,omitempty"`
}

// paginatedRepos is the Bitbucket response shape for repo listings.
type paginatedRepos struct {
	Values []repoRef `json:"values"`
	Next   string    `json:"next,omitempty"`
}

// Chunks walks every targeted repo and emits one Chunk per default-branch
// file. Per-repo failures (404, transient 5xx, permission) are tolerated —
// we keep walking the rest rather than aborting the whole scan.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	repos, err := c.listRepos(ctx)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.scanRepo(ctx, repo, ch); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

// listRepos resolves the configured scope into a slice of repoRef.
// Workspace enumeration paginates via Bitbucket's "next" URL field.
func (c *Connector) listRepos(ctx context.Context) ([]repoRef, error) {
	ws := c.cfg.Workspace
	if c.cfg.Repo != "" {
		parts := strings.SplitN(c.cfg.Repo, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("bitbucket: config.repo must be in workspace/slug form, got %q", c.cfg.Repo)
		}
		ws = parts[0]
		slug := parts[1]
		path := fmt.Sprintf("/2.0/repositories/%s/%s", ws, slug)
		var rr repoRef
		if _, err := c.client.GetJSON(ctx, path, &rr); err != nil {
			return nil, fmt.Errorf("bitbucket: get repo %s/%s: %w", ws, slug, err)
		}
		if rr.Workspace.Slug == "" {
			rr.Workspace.Slug = ws
		}
		if rr.Name == "" {
			rr.Name = slug
		}
		return []repoRef{rr}, nil
	}
	// Workspace enumeration.
	var repos []repoRef
	next := fmt.Sprintf("/2.0/repositories/%s?pagelen=100", ws)
	for next != "" {
		var page paginatedRepos
		if _, err := c.client.GetJSON(ctx, next, &page); err != nil {
			return nil, fmt.Errorf("bitbucket: list workspace %s repos: %w", ws, err)
		}
		repos = append(repos, page.Values...)
		next = page.Next
	}
	return repos, nil
}

// scanRepo walks the /src/{branch}/ directory listing and fans out file
// fetches.
func (c *Connector) scanRepo(ctx context.Context, repo repoRef, ch chan<- *sources.Chunk) error {
	branch := repo.MainBranch.Name
	if branch == "" {
		return nil
	}
	ws := repo.workspaceSlug()
	slug := repo.Name

	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, c.concurrency)

	next := fmt.Sprintf("/2.0/repositories/%s/%s/src/%s/?pagelen=100", ws, slug, branch)
	for next != "" {
		if err := gctx.Err(); err != nil {
			return err
		}
		var page paginatedSrc
		if _, err := c.client.GetJSON(gctx, next, &page); err != nil {
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
			if entry.Size > c.cfg.MaxFileBytes {
				continue
			}
			select {
			case sem <- struct{}{}:
			case <-gctx.Done():
				return gctx.Err()
			}
			g.Go(func() error {
				defer func() { <-sem }()
				return c.emitFile(gctx, ws, slug, branch, entry, ch)
			})
		}
		next = page.Next
	}
	return g.Wait()
}

// emitFile fetches the raw file content and pushes a Chunk. Per-file fetch
// errors are tolerated — a single vanished file must not abort the scan.
func (c *Connector) emitFile(ctx context.Context, workspace, slug, branch string, entry srcEntry, ch chan<- *sources.Chunk) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	// GET /2.0/repositories/{ws}/{slug}/src/{commit}/{path}
	path := fmt.Sprintf("/2.0/repositories/%s/%s/src/%s/%s", workspace, slug, branch, entry.Path)
	resp, err := c.client.Do(ctx, http.MethodGet, path, nil)
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

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.cfg.MaxFileBytes))
	if err != nil {
		return nil
	}

	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceBitbucket,
		SourceName: c.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Git: &sources.GitMeta{
				Repository: workspace + "/" + slug,
				Commit:     branch,
				File:       entry.Path,
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
// GET /2.0/user: 200 → verified, 401 → not verified, transport /
// unexpected status → error.
//
// Verify is independent of Init: the CLI can spin a fresh Connector,
// optionally SetAPIBase, and call Verify directly.
func (c *Connector) Verify(ctx context.Context, secret string) (bool, error) {
	base := c.cfg.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	cl := NewClient(base, "", "", secret, nil)
	resp, err := cl.Do(ctx, http.MethodGet, "/2.0/user", nil)
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

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)
