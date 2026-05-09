// Package notion is the SaaSConnector port for Notion workspaces.
//
// It satisfies sources.Source so the engine drives a Notion scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Scope for the connector port:
//
//   - Auth: Internal integration token Bearer (secret_* prefix).
//   - Source surface: workspace search (pages + databases), page content via
//     recursive block descent, database row enumeration.
//   - Verify: GET /users/me with the supplied token. 200 -> verified,
//     401 -> not verified.
//   - All requests pin Notion-Version: 2022-06-28.
//   - Rate limit: honour 429 + Retry-After.
package notion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/connectors/notion/markdown"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// NotionVersion is the pinned API version required on all requests.
const NotionVersion = "2022-06-28"

// DefaultAPIBase is the public Notion API root.
const DefaultAPIBase = "https://api.notion.com/v1"

// requestTimeout caps a single REST call. Large workspaces can return
// substantial search results, so the timeout is generous; the surrounding
// ctx is the real cancellation signal.
const requestTimeout = 60 * time.Second

const maxRetries = 5

func init() {
	connectors.Register("notion", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceNotion, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects. The CLI builds it from --token
// and NOTION_TOKEN env-var fallback; no auto-discovery from arbitrary
// disk locations.
type Config struct {
	// Token is a Notion internal integration token (secret_* prefix)
	// sent as Authorization: Bearer <token>.
	Token string `json:"token"`
	// APIBase overrides the REST root (for testing or Notion Enterprise).
	APIBase string `json:"api_base,omitempty"`
	// Query filters the workspace search. When empty, the connector
	// enumerates all pages and databases the integration has been
	// granted access to.
	Query string `json:"query,omitempty"`
}

// Connector is the Notion SaaSConnector. One instance per scan: Init
// validates config, Chunks streams page/database content, Verify probes
// /users/me.
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
func (c *Connector) Type() sources.SourceType { return sources.SourceNotion }

// Descriptor returns the static metadata the CLI introspects.
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "notion",
		SourceType: sources.SourceNotion,
		AuthModes: []connectors.AuthMode{
			connectors.AuthBearer,
		},
		Capabilities: connectors.CapSource | connectors.CapVerify,
	}
}

// Init parses the JSON config, validates auth, and wires up the
// rate-limit-aware HTTP client.
func (c *Connector) Init(ctx context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("notion: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" {
		return errors.New("notion: config.token is required (set --token or NOTION_TOKEN)")
	}
	if cfg.APIBase == "" {
		cfg.APIBase = DefaultAPIBase
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

// searchResult represents a page from the Notion search endpoint.
type searchResult struct {
	Object  string       `json:"object"`
	Results []searchItem `json:"results"`
	Next    string       `json:"next_cursor"`
	HasMore bool         `json:"has_more"`
}

// searchItem is a generic Notion object (page or database) from search.
type searchItem struct {
	Object string          `json:"object"`
	ID     string          `json:"id"`
	URL    string          `json:"url"`
	Title  json.RawMessage `json:"title,omitempty"` // database title
	Raw    json.RawMessage // full JSON
}

// blockChildrenResp is the paginated response from GET /blocks/{id}/children.
type blockChildrenResp struct {
	Results []json.RawMessage `json:"results"`
	Next    string            `json:"next_cursor"`
	HasMore bool              `json:"has_more"`
}

// dbQueryResult represents a page from POST /databases/{id}/query.
type dbQueryResult struct {
	Results []json.RawMessage `json:"results"`
	Next    string            `json:"next_cursor"`
	HasMore bool              `json:"has_more"`
}

// Chunks walks the Notion workspace and emits one Chunk per page or
// database row. The flow is:
//
//  1. Workspace search: POST /search with page_size=100, paginated by
//     start_cursor.
//  2. For each page result: recursive block descent via
//     GET /blocks/{id}/children?page_size=100, paginated.
//  3. For each database result: POST /databases/{id}/query with
//     page_size=100, paginated.
//  4. Convert blocks to text via the markdown sub-package.
//  5. Emit one Chunk per page/database row.
//
// Per-item failures (404 on a page, transient 5xx) are tolerated — we
// keep walking the rest of the workspace. Only context cancellation
// aborts the whole scan.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	nextCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := map[string]any{
			"page_size": 100,
		}
		if c.cfg.Query != "" {
			body["query"] = c.cfg.Query
		}
		if nextCursor != "" {
			body["start_cursor"] = nextCursor
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("notion: marshal search body: %w", err)
		}
		resp, err := c.client.PostJSON(ctx, "/search", bodyJSON)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("notion: search: %w", err)
		}
		var sr searchResult
		if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
			resp.Body.Close()
			return fmt.Errorf("notion: decode search: %w", err)
		}
		resp.Body.Close()

		for i := range sr.Results {
			item := &sr.Results[i]
			itemRaw, _ := json.Marshal(item)
			item.Raw = itemRaw
			if err := ctx.Err(); err != nil {
				return err
			}
			switch item.Object {
			case "page":
				if err := c.emitPage(ctx, ch, *item); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			case "database":
				if err := c.emitDatabaseRows(ctx, ch, *item); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			}
		}

		if !sr.HasMore || sr.Next == "" {
			break
		}
		nextCursor = sr.Next
	}
	return nil
}

// emitPage fetches a page's title and all its block children recursively,
// converts them to Markdown, and emits a single Chunk with NotionMeta.
func (c *Connector) emitPage(ctx context.Context, ch chan<- *sources.Chunk, item searchItem) error {
	pageResp, err := c.client.GetJSON(ctx, "/pages/"+item.ID)
	if err != nil {
		return fmt.Errorf("notion: get page %s: %w", item.ID, err)
	}
	var pageFull struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.NewDecoder(pageResp.Body).Decode(&pageFull); err != nil {
		pageResp.Body.Close()
		return fmt.Errorf("notion: decode page %s: %w", item.ID, err)
	}
	pageResp.Body.Close()

	title := extractTitleFromProperties(pageFull.Properties)
	blocks, err := c.fetchAllBlocks(ctx, item.ID)
	if err != nil {
		return err
	}
	text := "# " + title + "\n\n" + markdown.ConvertBlocks(blocks)
	meta := &sources.NotionMeta{
		PageID: item.ID,
		Title:  title,
		URL:    item.URL,
		Part:   "page",
	}
	return c.sendChunk(ctx, ch, text, meta)
}

// emitDatabaseRows queries all rows from a database and emits one Chunk per
// row with NotionMeta. Each row's properties are serialised as text for
// detector scanning.
func (c *Connector) emitDatabaseRows(ctx context.Context, ch chan<- *sources.Chunk, item searchItem) error {
	path := fmt.Sprintf("/databases/%s/query", item.ID)
	nextCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := map[string]any{"page_size": 100}
		if nextCursor != "" {
			body["start_cursor"] = nextCursor
		}
		bodyJSON, _ := json.Marshal(body)
		resp, err := c.client.PostJSON(ctx, path, bodyJSON)
		if err != nil {
			return fmt.Errorf("notion: query database %s: %w", item.ID, err)
		}
		var qr dbQueryResult
		if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
			resp.Body.Close()
			return fmt.Errorf("notion: decode database query: %w", err)
		}
		resp.Body.Close()

		for _, row := range qr.Results {
			var pageObj struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			}
			_ = json.Unmarshal(row, &pageObj)
			text := extractRowText(row)
			meta := &sources.NotionMeta{
				PageID:   pageObj.ID,
				Database: item.ID,
				URL:      pageObj.URL,
				Part:     "database_row:" + pageObj.ID,
			}
			if err := c.sendChunk(ctx, ch, text, meta); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}

		if !qr.HasMore || qr.Next == "" {
			break
		}
		nextCursor = qr.Next
	}
	return nil
}

// fetchAllBlocks recursively fetches all block children for a parent block,
// paginating through the children endpoint and recursing into blocks with
// has_children=true.
func (c *Connector) fetchAllBlocks(ctx context.Context, parentID string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	nextCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		path := fmt.Sprintf("/blocks/%s/children?page_size=100", parentID)
		if nextCursor != "" {
			path += "&start_cursor=" + nextCursor
		}
		resp, err := c.client.GetJSON(ctx, path)
		if err != nil {
			return nil, fmt.Errorf("notion: get block children for %s: %w", parentID, err)
		}
		var bcr blockChildrenResp
		if err := json.NewDecoder(resp.Body).Decode(&bcr); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("notion: decode block children: %w", err)
		}
		resp.Body.Close()

		for _, raw := range bcr.Results {
			var b struct {
				HasChildren bool   `json:"has_children"`
				ID          string `json:"id"`
			}
			_ = json.Unmarshal(raw, &b)
			if b.HasChildren {
				children, err := c.fetchAllBlocks(ctx, b.ID)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return nil, err
					}
				} else {
					raw = injectChildren(raw, children)
				}
			}
			all = append(all, raw)
		}

		if !bcr.HasMore || bcr.Next == "" {
			break
		}
		nextCursor = bcr.Next
	}
	return all, nil
}

// injectChildren merges a children array into a block's JSON so the
// markdown converter can render nested blocks.
func injectChildren(blockJSON json.RawMessage, children []json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(blockJSON, &obj); err != nil {
		return blockJSON
	}
	childrenJSON, err := json.Marshal(children)
	if err != nil {
		return blockJSON
	}
	obj["children"] = childrenJSON
	result, err := json.Marshal(obj)
	if err != nil {
		return blockJSON
	}
	return result
}

// sendChunk emits a single Chunk on the channel, honouring backpressure.
func (c *Connector) sendChunk(ctx context.Context, ch chan<- *sources.Chunk, text string, meta *sources.NotionMeta) error {
	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceNotion,
		SourceName: c.name,
		Data:       []byte(text),
		SourceMetadata: sources.Metadata{
			Notion: meta,
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

// extractTitleFromProperties extracts the plain-text title from a page's
// properties map.
func extractTitleFromProperties(properties map[string]json.RawMessage) string {
	for _, propRaw := range properties {
		var prop struct {
			Type  string `json:"type"`
			Title []struct {
				PlainText string `json:"plain_text"`
			} `json:"title"`
		}
		if err := json.Unmarshal(propRaw, &prop); err != nil {
			continue
		}
		if prop.Type == "title" && len(prop.Title) > 0 {
			var parts []string
			for _, t := range prop.Title {
				parts = append(parts, t.PlainText)
			}
			return strings.Join(parts, "")
		}
	}
	return ""
}

// extractRowText serialises a database row's property values into
// a newline-separated text string for detector scanning.
func extractRowText(raw json.RawMessage) string {
	var row struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return string(raw)
	}
	var lines []string
	for name, propRaw := range row.Properties {
		text := extractPropertyValue(propRaw)
		if text != "" {
			lines = append(lines, name+": "+text)
		}
	}
	return strings.Join(lines, "\n")
}

// extractPropertyValue extracts the text content from a Notion property
// value (title, rich_text, url, email, phone_number, number, select,
// multi_select, date, people, checkbox, formula).
func extractPropertyValue(raw json.RawMessage) string {
	var prop struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &prop); err != nil {
		return ""
	}
	switch prop.Type {
	case "title", "rich_text":
		var items []struct {
			PlainText string `json:"plain_text"`
		}
		var wrapper map[string]json.RawMessage
		_ = json.Unmarshal(raw, &wrapper)
		if arr, ok := wrapper[prop.Type]; ok {
			_ = json.Unmarshal(arr, &items)
		}
		var parts []string
		for _, item := range items {
			parts = append(parts, item.PlainText)
		}
		return strings.Join(parts, "")
	case "url", "email", "phone_number", "number":
		var wrapper map[string]any
		_ = json.Unmarshal(raw, &wrapper)
		if v, ok := wrapper[prop.Type]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
	case "select":
		var wrapper struct {
			Select struct {
				Name string `json:"name"`
			} `json:"select"`
		}
		_ = json.Unmarshal(raw, &wrapper)
		return wrapper.Select.Name
	case "multi_select":
		var wrapper struct {
			MultiSelect []struct {
				Name string `json:"name"`
			} `json:"multi_select"`
		}
		_ = json.Unmarshal(raw, &wrapper)
		var names []string
		for _, s := range wrapper.MultiSelect {
			names = append(names, s.Name)
		}
		return strings.Join(names, ", ")
	case "date":
		var wrapper struct {
			Date struct {
				Start string `json:"start"`
				End   string `json:"end"`
			} `json:"date"`
		}
		_ = json.Unmarshal(raw, &wrapper)
		if wrapper.Date.Start != "" {
			return wrapper.Date.Start
		}
		return wrapper.Date.End
	case "checkbox":
		var wrapper map[string]bool
		_ = json.Unmarshal(raw, &wrapper)
		if v, ok := wrapper["checkbox"]; ok {
			if v {
				return "true"
			}
			return "false"
		}
	case "formula":
		var wrapper struct {
			Formula struct {
				Type    string   `json:"type"`
				String  string   `json:"string"`
				Number  *float64 `json:"number"`
				Boolean bool     `json:"boolean"`
			} `json:"formula"`
		}
		_ = json.Unmarshal(raw, &wrapper)
		switch wrapper.Formula.Type {
		case "string":
			return wrapper.Formula.String
		case "number":
			if wrapper.Formula.Number != nil {
				return fmt.Sprintf("%v", *wrapper.Formula.Number)
			}
		case "boolean":
			if wrapper.Formula.Boolean {
				return "true"
			}
			return "false"
		}
	case "people":
		var wrapper struct {
			People []struct {
				Name string `json:"name"`
			} `json:"people"`
		}
		_ = json.Unmarshal(raw, &wrapper)
		var names []string
		for _, p := range wrapper.People {
			names = append(names, p.Name)
		}
		return strings.Join(names, ", ")
	}
	return ""
}

// Verify implements detectors.Verifier. GET /users/me: 200 -> true,
// 401 -> false, transport errors bubble up.
func (c *Connector) Verify(ctx context.Context, secret string) (bool, error) {
	base := c.cfg.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	cl := NewClient(base, secret, nil)
	resp, err := cl.GetJSON(ctx, "/users/me")
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
		return false, fmt.Errorf("notion: verify unexpected status %s", resp.Status)
	}
}

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)

// ---- Client --------------------------------------------------------------

// Client is a small, rate-limit-aware Notion REST client. It backs off on
// 429 responses honouring Retry-After.
type Client struct {
	base          string
	token         string
	http          *http.Client
	notionVersion string
}

// NewClient constructs a Client. httpClient may be nil.
func NewClient(base, token string, httpClient *http.Client) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{base: base, token: token, http: httpClient, notionVersion: NotionVersion}
}

// Do issues an HTTP request against the Notion API with retry on 429.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Notion-Version", c.notionVersion)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := retryAfter(resp)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if wait <= 0 {
				wait = time.Second * time.Duration(1<<uint(attempt))
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
	return nil, errors.New("notion: exhausted retries against rate limit")
}

// GetJSON issues a GET and returns the raw response (caller reads body).
func (c *Client) GetJSON(ctx context.Context, path string) (*http.Response, error) {
	return c.Do(ctx, http.MethodGet, path, nil)
}

// PostJSON issues a POST with a JSON body and returns the raw response.
func (c *Client) PostJSON(ctx context.Context, path string, body []byte) (*http.Response, error) {
	return c.Do(ctx, http.MethodPost, path, strings.NewReader(string(body)))
}

// url returns the absolute URL. Relative paths are joined onto the base.
func (c *Client) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

// retryAfter extracts the Retry-After duration from a 429 response.
func retryAfter(resp *http.Response) time.Duration {
	v := resp.Header.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
