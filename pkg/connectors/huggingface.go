// HuggingFace connector. Single-file handler shape: auth, enumerate repos,
// clone via git, bridge chunks.
//
// Surface: models, datasets, and spaces owned by an organisation (or a single
// named repo). Each repo is cloned via smart-HTTP and its full commit history
// is walked by the git source — zero HuggingFace API cost per file.
//
// Auth: HuggingFace user-access token. REST requests send
// `Authorization: Bearer <token>`; git smart-HTTP clones authenticate as
// `x-access-token:<token>` HTTP Basic.
//
// Pagination: HuggingFace returns results in pages; advance via the `p` query
// parameter and stop when an empty page is returned.
//
// Config keys:
//   - token       (optional for public repos) HuggingFace user-access token
//   - org         organisation (author) name to enumerate
//   - repo        single repo in "owner/name" form (mutually exclusive with org)
//   - api_base    override https://huggingface.co (for proxies / mirrors)
//   - repo_types  comma-separated subset of "model,dataset,space" (default: all)

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	gogit "github.com/go-git/go-git/v5"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	"github.com/plenoai/pleno-dlp/pkg/sources"
	gitsource "github.com/plenoai/pleno-dlp/pkg/sources/git"
)

const (
	hfDefaultAPIBase      = "https://huggingface.co"
	hfRequestTimeout      = 60 * time.Second
	hfPageSize            = 100
	hfDefaultRepoTypes    = "model,dataset,space"
)

func init() {
	Register("huggingface", Connector{
		SourceType:  sources.SourceHuggingFace,
		Scan:        scanHuggingFace,
		Verify:      verifyHuggingFace,
		Fingerprint: fingerprintHuggingFace,
	})
}

// scanHuggingFace is the connector entry point.
func scanHuggingFace(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	org := cfg["org"]
	repo := cfg["repo"]
	if org == "" && repo == "" {
		return errors.New("huggingface: either org or repo must be set")
	}
	if org != "" && repo != "" {
		return errors.New("huggingface: org and repo are mutually exclusive")
	}
	apiBase := cfg.Get("api_base", hfDefaultAPIBase)

	cli := newHFClient(apiBase, token)
	repos, err := hfListRepos(ctx, cli, org, repo, cfg.Get("repo_types", hfDefaultRepoTypes))
	if err != nil {
		return err
	}

	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanHFRepo(ctx, cfg, cli, r, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Per-repo failures are tolerated — continue with remaining repos.
			continue
		}
	}
	return nil
}

// scanHFRepo clones one repo and walks its full commit history.
func scanHFRepo(ctx context.Context, cfg Config, cli *hfClient, repo hfRepoRef, emit Emit) error {
	cloneURL := hfBuildCloneURL(cfg, repo)

	dir, err := os.MkdirTemp("", "pleno-hf-clone-")
	if err != nil {
		return fmt.Errorf("huggingface: mktemp for clone: %w", err)
	}
	defer os.RemoveAll(dir)

	cloneOpts := &gogit.CloneOptions{URL: cloneURL}
	if cli.token != "" {
		cloneOpts.Auth = &githttp.BasicAuth{
			Username: "x-access-token",
			Password: cli.token,
		}
	}
	if _, err := gogit.PlainCloneContext(ctx, dir, true, cloneOpts); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("huggingface: clone %s/%s: %w", repo.Author, repo.ID, err)
	}

	src := &gitsource.Source{}
	gitCfg := gitsource.Config{Repo: dir, AllBranches: true}
	raw, err := json.Marshal(gitCfg)
	if err != nil {
		return err
	}
	if err := src.Init(ctx, "huggingface", 0, 0, false, raw, 1); err != nil {
		return fmt.Errorf("huggingface: init git walk for %s/%s: %w", repo.Author, repo.ID, err)
	}

	// Bridge the git source's Chunk channel into the connector Emit,
	// rewriting GitMeta → HuggingFaceMeta.
	ch := make(chan *sources.Chunk, 64)
	walkErr := make(chan error, 1)
	go func() {
		walkErr <- src.Chunks(ctx, ch)
		close(ch)
	}()

	// Derive the short repo name from the modelId/repoId field (e.g.
	// "org/name" → "name"; bare "name" → "name").
	repoName := repo.ID
	if idx := strings.LastIndex(repoName, "/"); idx >= 0 {
		repoName = repoName[idx+1:]
	}

	var emitErr error
	for c := range ch {
		if emitErr != nil {
			continue // drain
		}
		gm := c.SourceMetadata.Git
		if gm == nil {
			continue
		}
		meta := sources.Metadata{
			HuggingFace: &sources.HuggingFaceMeta{
				Organization: repo.Author,
				Repository:   repoName,
				RepoType:     repo.Type,
				Path:         gm.File,
				Commit:       gm.Commit,
			},
		}
		if err := emit(c.Data, meta); err != nil {
			emitErr = err
		}
	}
	if err := <-walkErr; err != nil {
		return err
	}
	return emitErr
}

// verifyHuggingFace calls GET /api/whoami-v2 with the supplied token.
func verifyHuggingFace(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", hfDefaultAPIBase)
	cli := newHFClient(apiBase, secret)
	resp, err := cli.do(ctx, http.MethodGet, "/api/whoami-v2", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		return false, nil
	default:
		return false, fmt.Errorf("huggingface: verify unexpected status %s", resp.Status)
	}
}

// fingerprintHuggingFace returns a stable digest of the repos that would be
// scanned, based on their IDs and sha fields.
func fingerprintHuggingFace(ctx context.Context, cfg Config) (string, error) {
	org := cfg["org"]
	repo := cfg["repo"]
	if org == "" && repo == "" {
		return "", errors.New("huggingface: either org or repo must be set")
	}
	apiBase := cfg.Get("api_base", hfDefaultAPIBase)
	cli := newHFClient(apiBase, cfg["token"])
	repos, err := hfListRepos(ctx, cli, org, repo, cfg.Get("repo_types", hfDefaultRepoTypes))
	if err != nil {
		return "", err
	}
	sort.Slice(repos, func(i, j int) bool {
		return repos[i].ID < repos[j].ID
	})

	h := sha256.New()
	writeFingerprint(h, "huggingface-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, org)
	writeFingerprint(h, repo)
	writeFingerprint(h, cfg.Get("repo_types", hfDefaultRepoTypes))
	for _, r := range repos {
		writeFingerprint(h, r.ID)
		writeFingerprint(h, r.SHA)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// --- HuggingFace API types ---

type hfRepoRef struct {
	ID     string `json:"modelId"` // primary for models; also used for datasets/spaces
	Author string `json:"author"`
	SHA    string `json:"sha"`
	Type   string `json:"-"` // filled in by hfListRepos
}

// hfListRepos enumerates repos by type(s) for the given org, or resolves a
// single named repo.
func hfListRepos(ctx context.Context, cli *hfClient, org, singleRepo, repoTypes string) ([]hfRepoRef, error) {
	if singleRepo != "" {
		return hfResolveSingleRepo(ctx, cli, singleRepo, repoTypes)
	}

	types := parseRepoTypes(repoTypes)
	var all []hfRepoRef
	for _, rt := range types {
		repos, err := hfEnumerateByType(ctx, cli, org, rt)
		if err != nil {
			return nil, err
		}
		all = append(all, repos...)
	}
	return all, nil
}

// hfResolveSingleRepo tries to look up a named repo across the enabled types.
// The API does not have a unified "get repo" endpoint, so we probe each type.
func hfResolveSingleRepo(ctx context.Context, cli *hfClient, singleRepo, repoTypes string) ([]hfRepoRef, error) {
	parts := strings.SplitN(singleRepo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("huggingface: repo must be in owner/name form, got %q", singleRepo)
	}
	owner, name := parts[0], parts[1]
	types := parseRepoTypes(repoTypes)
	apiEndpoints := map[string]string{
		"model":   "/api/models/" + owner + "/" + name,
		"dataset": "/api/datasets/" + owner + "/" + name,
		"space":   "/api/spaces/" + owner + "/" + name,
	}
	for _, rt := range types {
		ep, ok := apiEndpoints[rt]
		if !ok {
			continue
		}
		var r hfRepoRef
		if err := cli.getJSON(ctx, ep, &r); err != nil {
			continue
		}
		if r.ID == "" {
			r.ID = owner + "/" + name
		}
		if r.Author == "" {
			r.Author = owner
		}
		r.Type = rt
		return []hfRepoRef{r}, nil
	}
	return nil, fmt.Errorf("huggingface: repo %q not found in types %v", singleRepo, types)
}

// hfEnumerateByType lists all repos of a given type for an org.
func hfEnumerateByType(ctx context.Context, cli *hfClient, org, repoType string) ([]hfRepoRef, error) {
	pluralPath := map[string]string{
		"model":   "/api/models",
		"dataset": "/api/datasets",
		"space":   "/api/spaces",
	}
	basePath, ok := pluralPath[repoType]
	if !ok {
		return nil, fmt.Errorf("huggingface: unknown repo type %q", repoType)
	}

	var all []hfRepoRef
	for page := 0; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := fmt.Sprintf("%s?author=%s&full=false&limit=%d&p=%d",
			basePath, url.QueryEscape(org), hfPageSize, page)
		var repos []hfRepoRef
		if err := cli.getJSON(ctx, path, &repos); err != nil {
			return nil, fmt.Errorf("huggingface: list %s page %d: %w", repoType, page, err)
		}
		for i := range repos {
			repos[i].Type = repoType
		}
		all = append(all, repos...)
		if len(repos) < hfPageSize {
			break
		}
	}
	return all, nil
}

// parseRepoTypes splits a comma-separated repo_types string into a slice,
// trimming spaces and dropping unknowns.
func parseRepoTypes(s string) []string {
	valid := map[string]bool{"model": true, "dataset": true, "space": true}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if valid[p] {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"model", "dataset", "space"}
	}
	return out
}

// hfBuildCloneURL resolves the clone URL for a repo, honouring the
// clone_url_template config key (test-only override, same convention as the
// GitHub connector). The template supports {owner} and {repo} placeholders.
func hfBuildCloneURL(cfg Config, repo hfRepoRef) string {
	if tmpl := cfg["clone_url_template"]; tmpl != "" {
		name := repo.ID
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		u := strings.ReplaceAll(tmpl, "{owner}", repo.Author)
		u = strings.ReplaceAll(u, "{repo}", name)
		return u
	}
	return hfCloneURL(cfg.Get("api_base", hfDefaultAPIBase), repo.Author, repo.ID)
}

// hfCloneURL builds the smart-HTTP clone URL for a HuggingFace repo.
// For models: https://huggingface.co/{owner}/{name}.git
// For datasets: https://huggingface.co/datasets/{owner}/{name}.git
// For spaces:   https://huggingface.co/spaces/{owner}/{name}.git
// The repoID from the API is typically "owner/name"; we take the last segment.
func hfCloneURL(apiBase, owner, repoID string) string {
	name := repoID
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	base := strings.TrimRight(apiBase, "/")
	return fmt.Sprintf("%s/%s/%s.git", base, owner, name)
}

// --- HTTP client ---

type hfClient struct {
	base  string
	token string
	http  *http.Client
}

func newHFClient(base, token string) *hfClient {
	if base == "" {
		base = hfDefaultAPIBase
	}
	return &hfClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: hfRequestTimeout},
	}
}

func (c *hfClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		u = c.base + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return c.http.Do(req)
}

func (c *hfClient) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("huggingface: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("huggingface: decode %s: %w", path, err)
		}
	}
	return nil
}
