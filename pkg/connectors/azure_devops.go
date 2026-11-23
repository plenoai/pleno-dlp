// Azure DevOps Repos connector. Enumerates the Git repositories of an
// organization (optionally one project) and walks each one's full history
// through the shared scanRemoteGitRepo clone walker.
//
// Surface:
//   - GET {org}[/{project}]/_apis/git/repositories?api-version=7.1
//   - clone of each repository's remoteUrl (all branches and tags)
//
// Auth: Personal Access Token (Code: Read) sent as HTTP Basic with an
// empty username, for both the REST API and the Git clone. The PAT is
// only sent to HTTPS (or loopback HTTP) endpoints.
//
// Incremental: the git source's per-ref state is checkpointed per
// repository and flushed after each one, so a re-scan only walks new
// commits and an interrupted scan resumes at the next repository.
//
// Upstream reference: mongodb/kingfisher src/azure.rs.

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
)

const (
	azureDevOpsDefaultBaseURL = "https://dev.azure.com"
	azureDevOpsAPIVersion     = "7.1"
	azureDevOpsTimeout        = 60 * time.Second
	// azureDevOpsCloneUser is sent with the PAT; Azure DevOps ignores the
	// username but Git requires a non-empty one.
	azureDevOpsCloneUser = "pat"
)

func init() {
	Register("azure-devops", Connector{
		SourceType:  sources.SourceAzureDevOps,
		Scan:        scanAzureDevOps,
		Verify:      verifyAzureDevOps,
		Fingerprint: fingerprintAzureDevOps,
	})
}

type azureDevOpsClient struct {
	base    string // scheme://host[/path]/{org}
	pat     string
	project string
	http    *http.Client
}

type azureDevOpsRepo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	RemoteURL  string `json:"remoteUrl"`
	IsDisabled bool   `json:"isDisabled"`
	Size       int64  `json:"size"`
	Project    struct {
		Name string `json:"name"`
	} `json:"project"`
}

type azureDevOpsIncrementalState struct {
	Version int                        `json:"version"`
	Repos   map[string]json.RawMessage `json:"repos"`
}

// newAzureDevOpsClient cfg keys:
//   - token     (required) PAT
//   - org       (required) organization name
//   - project   restrict to one project
//   - base_url  override https://dev.azure.com (Azure DevOps Server: https://host/tfs)
func newAzureDevOpsClient(cfg Config, pat string) (*azureDevOpsClient, error) {
	if pat == "" {
		return nil, errors.New("azure-devops: token is required (set --token or AZURE_DEVOPS_PAT)")
	}
	org := strings.Trim(cfg["org"], "/")
	if org == "" || strings.Contains(org, "/") {
		return nil, fmt.Errorf("azure-devops: org must be a single organization name, got %q", cfg["org"])
	}
	base := strings.TrimRight(cfg.Get("base_url", azureDevOpsDefaultBaseURL), "/")
	if err := requireSecureEndpoint("azure-devops", base); err != nil {
		return nil, err
	}
	return &azureDevOpsClient{
		base:    base + "/" + url.PathEscape(org),
		pat:     pat,
		project: cfg["project"],
		http:    authenticatedHTTPClient(azureDevOpsTimeout),
	}, nil
}

func (c *azureDevOpsClient) get(ctx context.Context, path string, out any) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return 0, err
	}
	req.SetBasicAuth("", c.pat)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("azure-devops: GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return resp.StatusCode, fmt.Errorf("azure-devops: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("azure-devops: decode %s: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}

func (c *azureDevOpsClient) listRepos(ctx context.Context) ([]azureDevOpsRepo, error) {
	path := "/_apis/git/repositories?api-version=" + azureDevOpsAPIVersion
	if c.project != "" {
		path = "/" + url.PathEscape(c.project) + path
	}
	var page struct {
		Value []azureDevOpsRepo `json:"value"`
	}
	if _, err := c.get(ctx, path, &page); err != nil {
		return nil, err
	}
	return page.Value, nil
}

// cloneURL strips the "org@" userinfo Azure DevOps embeds in remoteUrl;
// credentials are passed separately so they never appear in the URL.
func (r azureDevOpsRepo) cloneURL() string {
	u, err := url.Parse(r.RemoteURL)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

func scanAzureDevOps(ctx context.Context, cfg Config, emit Emit) error {
	cli, err := newAzureDevOpsClient(cfg, cfg["token"])
	if err != nil {
		return err
	}
	previous := azureDevOpsIncrementalState{}
	if raw := cfg[configKeyIncrementalPreviousState]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &previous); err != nil {
			return fmt.Errorf("azure-devops: parse incremental source state: %w", err)
		}
	}
	next := azureDevOpsIncrementalState{Version: 1, Repos: map[string]json.RawMessage{}}
	flush := IncrementalFlushFromContext(ctx)
	cfg[configKeyIncrementalPartialSafe] = "true"

	repos, err := cli.listRepos(ctx)
	if err != nil {
		return err
	}
	var failures []engine.ScanFailure
	var skipped int
	for _, r := range repos {
		if err := ctx.Err(); err != nil {
			return err
		}
		key := r.Project.Name + "/" + r.Name
		if r.IsDisabled {
			skipped++
			if st, ok := previous.Repos[key]; ok {
				next.Repos[key] = st
			}
			continue
		}
		target := remoteGitRepo{Key: key, CloneURL: r.cloneURL()}
		if strings.HasPrefix(target.CloneURL, "https://") || strings.HasPrefix(target.CloneURL, "http://") {
			target.Username = azureDevOpsCloneUser
			target.Password = cli.pat
		}
		markedEmit := func(data []byte, meta sources.Metadata) error {
			if err := emit(data, meta); err != nil {
				return azureDevOpsEmitError{err}
			}
			return nil
		}
		state, err := scanRemoteGitRepo(ctx, "azure-devops", target, previous.Repos[key], markedEmit)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			// A failed emit means the sink is gone: abort. Clone and walk
			// failures only cost this repository's coverage.
			var ee azureDevOpsEmitError
			if errors.As(err, &ee) {
				return ee.err
			}
			failures = append(failures, engine.ScanFailure{Kind: engine.FailureSource, Source: "azure-devops/" + key, Err: err})
			if st, ok := previous.Repos[key]; ok {
				next.Repos[key] = st // keep the old checkpoint so the repo is retried from it
			}
			continue
		}
		if len(state) > 0 {
			next.Repos[key] = state
		}
		if flush != nil {
			if data, err := json.Marshal(next); err == nil {
				if ferr := flush(data); ferr != nil {
					termsafe.Fprintf(os.Stderr, "WARN: azure-devops incremental flush failed after %s: %v\n", key, ferr)
				}
			}
		}
	}
	if skipped > 0 {
		termsafe.Fprintf(os.Stderr, "azure-devops: skipped disabled repositories=%d\n", skipped)
	}
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("azure-devops: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	if len(failures) > 0 {
		return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
	}
	return nil
}

// fingerprintAzureDevOps returns "": there is no cheap fingerprint over
// every ref of every repository, so the --incremental skip fast-path is
// disabled and the per-repo git state does the incremental work.
func fingerprintAzureDevOps(_ context.Context, cfg Config) (string, error) {
	if _, err := newAzureDevOpsClient(cfg, cfg["token"]); err != nil {
		return "", err
	}
	return "", nil
}

// verifyAzureDevOps checks the PAT against the organization's project list.
func verifyAzureDevOps(ctx context.Context, cfg Config, secret string) (bool, error) {
	cli, err := newAzureDevOpsClient(cfg, secret)
	if err != nil {
		return false, err
	}
	status, err := cli.get(ctx, "/_apis/projects?api-version="+azureDevOpsAPIVersion+"&$top=1", nil)
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNonAuthoritativeInfo:
		return false, nil
	}
	return false, err
}

// azureDevOpsEmitError marks errors returned by emit so they abort the scan
// instead of being recorded as one repository's degraded coverage.
type azureDevOpsEmitError struct{ err error }

func (e azureDevOpsEmitError) Error() string { return e.err.Error() }
func (e azureDevOpsEmitError) Unwrap() error { return e.err }
