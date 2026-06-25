// CircleCI connector. Scans CircleCI project pipeline configurations for secrets.
//
// Surface:
//   - GET /api/v1.1/projects to enumerate all followed projects
//   - GET /api/v2/project/{slug}/pipeline to list recent pipelines per project
//   - GET /api/v2/pipeline/{id}/config to fetch the pipeline config.yml
//
// Auth: CircleCI personal API token (Circle-Token header).
// Verify hits GET /api/v2/me to confirm token validity.
//
// Config keys:
//   - token         (required) CircleCI personal API token
//   - base_url      override https://circleci.com (for testing)
//   - max_pipelines per-project pipeline scan limit (default 5)

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	circleciBaseURL      = "https://circleci.com"
	circleciTimeout      = 60 * time.Second
	circleciMaxPipelines = 5
	circleciMaxConfig    = 2 << 20 // 2 MiB
)

func init() {
	Register("circleci", Connector{
		SourceType:  sources.SourceCircleCI,
		Scan:        scanCircleCI,
		Verify:      verifyCircleCI,
		Fingerprint: fingerprintCircleCI,
	})
}

// scanCircleCI enumerates all followed projects and emits each project's recent
// pipeline configurations (config.yml) as chunks.
//
// cfg keys:
//   - token         (required) CircleCI personal API token
//   - base_url      override https://circleci.com
//   - max_pipelines max pipelines to scan per project (default 5)
func scanCircleCI(ctx context.Context, cfg Config, emit Emit) error {
	cli, err := newCircleCIClient(cfg)
	if err != nil {
		return err
	}

	projects, err := cli.listProjects(ctx)
	if err != nil {
		return fmt.Errorf("circleci: list projects: %w", err)
	}

	for _, proj := range projects {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := circleciEmitProject(ctx, cli, proj, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Per-project errors are non-fatal.
		}
	}
	return nil
}

func circleciEmitProject(ctx context.Context, cli *circleciClient, proj circleciProject, emit Emit) error {
	pipelines, err := cli.listPipelines(ctx, proj.Slug)
	if err != nil {
		return nil // non-fatal: project may have no pipelines
	}

	limit := cli.maxPipelines
	if len(pipelines) < limit {
		limit = len(pipelines)
	}

	for _, pipeline := range pipelines[:limit] {
		if err := ctx.Err(); err != nil {
			return err
		}
		config, err := cli.getPipelineConfig(ctx, pipeline.ID)
		if err != nil || len(config) == 0 {
			continue
		}
		meta := sources.Metadata{
			SIEM: &sources.SIEMMeta{
				Provider: "circleci",
				Host:     cli.baseURL,
				Index:    proj.Slug,
				EventID:  "pipeline-" + pipeline.ID,
				Link:     fmt.Sprintf("https://app.circleci.com/pipelines/%s/%d", proj.Slug, pipeline.Number),
			},
		}
		if emitErr := emit(config, meta); emitErr != nil {
			if errors.Is(emitErr, context.Canceled) || errors.Is(emitErr, context.DeadlineExceeded) {
				return emitErr
			}
		}
	}
	return nil
}

func fingerprintCircleCI(ctx context.Context, cfg Config) (string, error) {
	cli, err := newCircleCIClient(cfg)
	if err != nil {
		return "", err
	}
	projects, err := cli.listProjects(ctx)
	if err != nil {
		return "", fmt.Errorf("circleci: list projects for fingerprint: %w", err)
	}
	h := sha256.New()
	writeFingerprint(h, "circleci-v1")
	writeFingerprint(h, cli.baseURL)
	for _, proj := range projects {
		writeFingerprint(h, proj.Slug)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func verifyCircleCI(ctx context.Context, cfg Config, secret string) (bool, error) {
	baseURL := cfg.Get("base_url", circleciBaseURL)
	tmpCfg := Config{"token": secret, "base_url": baseURL}
	cli, err := newCircleCIClient(tmpCfg)
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cli.baseURL+"/api/v2/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Circle-Token", cli.token)
	resp, err := cli.http.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK, nil
}

// --- internal types ---

type circleciClient struct {
	baseURL      string
	token        string
	maxPipelines int
	http         *http.Client
}

type circleciProject struct {
	Slug string
	Name string
}

type circleciPipeline struct {
	ID     string `json:"id"`
	Number int    `json:"number"`
}

func newCircleCIClient(cfg Config) (*circleciClient, error) {
	token := cfg["token"]
	if token == "" {
		return nil, errors.New("circleci: token is required (set --token or CIRCLE_TOKEN)")
	}
	baseURL := strings.TrimRight(cfg.Get("base_url", circleciBaseURL), "/")
	return &circleciClient{
		baseURL:      baseURL,
		token:        token,
		maxPipelines: circleciMaxPipelines,
		http:         &http.Client{Timeout: circleciTimeout},
	}, nil
}

func (c *circleciClient) doGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Circle-Token", c.token)
	req.Header.Set("Accept", "application/json")
	return c.http.Do(req)
}

// listProjects returns all projects the token can access via the v1.1 /projects endpoint.
func (c *circleciClient) listProjects(ctx context.Context) ([]circleciProject, error) {
	resp, err := c.doGet(ctx, "/api/v1.1/projects")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("circleci: list projects -> %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	var raw []struct {
		VCSType  string `json:"vcs_type"`
		Username string `json:"username"`
		Reponame string `json:"reponame"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("circleci: decode projects: %w", err)
	}
	projects := make([]circleciProject, 0, len(raw))
	for _, r := range raw {
		if r.VCSType == "" || r.Username == "" || r.Reponame == "" {
			continue
		}
		projects = append(projects, circleciProject{
			Slug: r.VCSType + "/" + r.Username + "/" + r.Reponame,
			Name: r.Reponame,
		})
	}
	return projects, nil
}

// listPipelines returns recent pipelines for the given project slug.
func (c *circleciClient) listPipelines(ctx context.Context, slug string) ([]circleciPipeline, error) {
	resp, err := c.doGet(ctx, "/api/v2/project/"+slug+"/pipeline")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("circleci: list pipelines for %s -> %s: %s", slug, resp.Status, strings.TrimSpace(string(b)))
	}
	var result struct {
		Items []circleciPipeline `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("circleci: decode pipelines: %w", err)
	}
	return result.Items, nil
}

// getPipelineConfig returns the config.yml source for the given pipeline ID.
func (c *circleciClient) getPipelineConfig(ctx context.Context, pipelineID string) ([]byte, error) {
	resp, err := c.doGet(ctx, "/api/v2/pipeline/"+pipelineID+"/config")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("circleci: get config for pipeline %s -> %s", pipelineID, resp.Status)
	}
	var result struct {
		Source string `json:"source"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, circleciMaxConfig)).Decode(&result); err != nil {
		return nil, fmt.Errorf("circleci: decode pipeline config: %w", err)
	}
	return []byte(result.Source), nil
}
