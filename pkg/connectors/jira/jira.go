// Package jira is the SaaSConnector port for Jira Cloud and Jira Data Center.
//
// It satisfies sources.Source so the engine drives a Jira scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Auth: Cloud uses Atlassian API token + email via HTTP Basic auth.
// Data Center uses Personal Access Token (PAT) via Bearer auth.
//
// Source surface:
//   - If `project` or `jql` is set, skip project enumeration and search
//     directly with the provided filter.
//   - Otherwise, enumerate projects via GET /rest/api/3/project/search
//     and search each project.
//   - Issue search: POST /rest/api/3/search with JQL, paginated via
//     startAt offset.
//   - Each issue description and each comment body are parsed (ADF for
//     Cloud, storage-format XHTML for Data Center) and emitted as
//     separate Chunks.
//
// Verify: GET /rest/api/3/myself — 200 → true, 401 → false.
package jira

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/connectors/jira/adf"
	"github.com/plenoai/pleno-dlp/pkg/connectors/jira/storage"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	// requestTimeout caps a single REST call.
	requestTimeout = 60 * time.Second

	// pageSize controls how many issues are fetched per search request.
	pageSize = 50
)

func init() {
	connectors.Register("jira", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceJira, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects.
type Config struct {
	// Email is the Atlassian account email (Cloud auth). Required for
	// Cloud; ignored for Data Center when PAT is used.
	Email string `json:"email,omitempty"`
	// Token is the API token (Cloud) or Personal Access Token (Data Center).
	Token string `json:"token"`
	// Project filters issues to a single project key (e.g. "PROJ").
	// If empty and JQL is empty, all accessible projects are enumerated.
	Project string `json:"project,omitempty"`
	// JQL is a raw JQL query. Overrides project when set.
	JQL string `json:"jql,omitempty"`
	// APIBase is the Jira REST root URL. For Cloud, typically
	// "https://<site>.atlassian.net". For Data Center, the on-premise URL.
	APIBase string `json:"api_base,omitempty"`
}

// Connector is the Jira SaaSConnector. One instance per scan.
type Connector struct {
	name        string
	jobID       int64
	sourceID    int64
	verify      bool
	concurrency int
	cfg         Config
	client      *http.Client
}

// Type returns the wire-stable SourceType for output formatters.
func (c *Connector) Type() sources.SourceType { return sources.SourceJira }

// Descriptor returns the static metadata the CLI introspects.
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "jira",
		SourceType: sources.SourceJira,
		AuthModes: []connectors.AuthMode{
			connectors.AuthBasic,
			connectors.AuthPAT,
		},
		Capabilities: connectors.CapSource | connectors.CapVerify,
	}
}

// SetAPIBase lets the CLI plumb `--api-base` for verify-only usage.
func (c *Connector) SetAPIBase(base string) {
	c.cfg.APIBase = base
}

// SetEmail lets the CLI plumb `--email` for verify-only usage (Cloud Basic auth).
func (c *Connector) SetEmail(email string) {
	c.cfg.Email = email
}

// Init parses the JSON config, validates auth, and wires up the HTTP client.
func (c *Connector) Init(ctx context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("jira: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" {
		return errors.New("jira: config.token is required (set --token or JIRA_TOKEN)")
	}
	if cfg.APIBase == "" {
		return errors.New("jira: config.api_base is required (set --site or --api-base)")
	}
	cfg.APIBase = strings.TrimRight(cfg.APIBase, "/")
	if concurrency <= 0 {
		concurrency = 1
	}
	c.name = name
	c.jobID = jobID
	c.sourceID = sourceID
	c.verify = verifyFlag
	c.concurrency = concurrency
	c.cfg = cfg
	c.client = &http.Client{Timeout: requestTimeout}
	return nil
}

// Chunks walks Jira issues and emits one Chunk per issue description and
// per comment body. Partial failures (one project 404s) are tolerated —
// the connector keeps walking the rest.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	projects, err := c.resolveProjects(ctx)
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
			// Per-project errors are tolerated.
			continue
		}
	}
	return nil
}

// projectEntry is a minimal representation of a Jira project.
type projectEntry struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// resolveProjects returns the list of project keys to scan.
// If JQL is set, no project enumeration is needed (a sentinel entry is
// returned; the search will use the raw JQL). If project is set, return
// just that. Otherwise, enumerate all accessible projects.
func (c *Connector) resolveProjects(ctx context.Context) ([]projectEntry, error) {
	if c.cfg.JQL != "" {
		// JQL is raw — search directly, no project enumeration.
		return []projectEntry{{Key: "", Name: "jql"}}, nil
	}
	if c.cfg.Project != "" {
		return []projectEntry{{Key: c.cfg.Project, Name: c.cfg.Project}}, nil
	}
	// Enumerate projects via GET /rest/api/3/project/search.
	var projects []projectEntry
	startAt := 0
	for {
		var resp projectSearchResp
		path := fmt.Sprintf("/rest/api/3/project/search?maxResults=%d&startAt=%d", pageSize, startAt)
		if err := c.getJSON(ctx, path, &resp); err != nil {
			return nil, fmt.Errorf("jira: list projects: %w", err)
		}
		for _, v := range resp.Values {
			projects = append(projects, projectEntry{Key: v.Key, Name: v.Name})
		}
		if resp.IsLast || len(resp.Values) == 0 {
			break
		}
		startAt += len(resp.Values)
	}
	if len(projects) == 0 {
		return nil, errors.New("jira: no accessible projects found")
	}
	return projects, nil
}

type projectSearchResp struct {
	Values []struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"values"`
	IsLast  bool `json:"isLast"`
	Total   int  `json:"total"`
	StartAt int  `json:"startAt"`
}

// scanProject searches for issues in a project and emits chunks.
func (c *Connector) scanProject(ctx context.Context, proj projectEntry, ch chan<- *sources.Chunk) error {
	jql := c.cfg.JQL
	if jql == "" {
		jql = fmt.Sprintf("project = %s", proj.Key)
	}

	startAt := 0
	for {
		body := searchReq{JQL: jql, MaxResults: pageSize, StartAt: startAt,
			Fields: []string{"summary", "description", "comment"}}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("jira: marshal search body: %w", err)
		}
		var resp searchResp
		if err := c.postJSON(ctx, "/rest/api/3/search", bodyJSON, &resp); err != nil {
			return fmt.Errorf("jira: search %s: %w", proj.Key, err)
		}
		for _, issue := range resp.Issues {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.emitIssue(ctx, issue, proj, ch)
		}
		if startAt+pageSize >= resp.Total {
			break
		}
		startAt += len(resp.Issues)
		if len(resp.Issues) == 0 {
			break
		}
	}
	return nil
}

type searchReq struct {
	JQL        string   `json:"jql"`
	MaxResults int      `json:"maxResults"`
	StartAt    int      `json:"startAt"`
	Fields     []string `json:"fields"`
}

type searchResp struct {
	StartAt    int     `json:"startAt"`
	MaxResults int     `json:"maxResults"`
	Total      int     `json:"total"`
	Issues     []issue `json:"issues"`
}

type issue struct {
	Key    string `json:"key"`
	Fields struct {
		Summary     string          `json:"summary"`
		Description json.RawMessage `json:"description"`
		Comments    commentWrap     `json:"comment"`
	} `json:"fields"`
}

type commentWrap struct {
	Comments []struct {
		ID   string          `json:"id"`
		Body json.RawMessage `json:"body"`
	} `json:"comments"`
}

// emitIssue parses an issue's description and comments and emits Chunks.
func (c *Connector) emitIssue(ctx context.Context, iss issue, proj projectEntry, ch chan<- *sources.Chunk) {
	// Description.
	if len(iss.Fields.Description) > 0 {
		text := parseContent(iss.Fields.Description)
		if text != "" {
			c.sendChunk(ctx, ch, text, iss.Key, "description", proj)
		}
	}
	// Comments.
	for _, com := range iss.Fields.Comments.Comments {
		if len(com.Body) > 0 {
			text := parseContent(com.Body)
			if text != "" {
				c.sendChunk(ctx, ch, text, iss.Key, "comment:"+com.ID, proj)
			}
		}
	}
}

func (c *Connector) sendChunk(ctx context.Context, ch chan<- *sources.Chunk, data string, issueKey, part string, proj projectEntry) {
	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceJira,
		SourceName: c.name,
		Data:       []byte(data),
		SourceMetadata: sources.Metadata{
			Jira: &sources.JiraMeta{
				Project:  proj.Key,
				IssueKey: issueKey,
				Part:     part,
			},
		},
		Verify: c.verify,
	}
	select {
	case ch <- chunk:
	case <-ctx.Done():
	}
}

// parseContent detects whether the content is ADF (JSON) or storage-format
// XHTML and delegates to the appropriate parser.
func parseContent(raw json.RawMessage) string {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" || trimmed == "null" {
		return ""
	}
	// Try ADF first (starts with '{' → JSON document).
	if trimmed[0] == '{' {
		text, err := adf.ToText(raw)
		if err == nil && text != "" {
			return text
		}
		// ADF parse failed; return raw as fallback.
		return trimmed
	}
	// Otherwise treat as storage-format XHTML.
	text, err := storage.ToTextString(trimmed)
	if err == nil && text != "" {
		return text
	}
	return trimmed
}

// Verify implements detectors.Verifier. GET /rest/api/3/myself —
// 200 → true, 401 → false, transport error → error.
func (c *Connector) Verify(ctx context.Context, secret string) (bool, error) {
	base := c.cfg.APIBase
	if base == "" {
		return false, errors.New("jira: api_base not set (use --site or --api-base)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/rest/api/3/myself", nil)
	if err != nil {
		return false, err
	}
	// For verify, we use the secret as the token. If email was set in
	// config, use Basic auth; otherwise Bearer (PAT / Data Center).
	if c.cfg.Email != "" {
		req.SetBasicAuth(c.cfg.Email, secret)
	} else {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := c.client.Do(req)
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
		return false, fmt.Errorf("jira: verify unexpected status %s", resp.Status)
	}
}

// getJSON issues a GET and decodes JSON into out.
func (c *Connector) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.APIBase+path, nil)
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// postJSON issues a POST with a JSON body and decodes the response.
func (c *Connector) postJSON(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.APIBase+path, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	c.setAuth(req)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(respBody)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// setAuth configures authentication on the request. Cloud uses Basic auth
// (email + token); Data Center uses Bearer token.
func (c *Connector) setAuth(req *http.Request) {
	if c.cfg.Email != "" {
		req.SetBasicAuth(c.cfg.Email, c.cfg.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	}
}

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)
