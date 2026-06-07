// Notion connector. Single-file Lambda-handler shape.
//
// Surface: workspace search → for each page, recursive block descent;
// for each database, row enumeration. Block JSON converts to Markdown
// via the pkg/connectors/notion/markdown helper.
//
// Auth: Internal integration token sent as Authorization: Bearer.
// Notion-Version: 2022-06-28 pinned on every request.
//
// Pagination: cursor pagination via `next_cursor` + `has_more` in the
// response body. Both /search (POST) and /databases/.../query (POST)
// take `start_cursor` / `page_size`; /blocks/.../children (GET) takes
// `?start_cursor=&page_size=`.

package connectors

import (
	"context"
	"encoding/json"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors/notion/markdown"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	notionVersion        = "2022-06-28"
	notionDefaultAPIBase = "https://api.notion.com/v1"
	notionRequestTimeout = 60 * time.Second
	notionMaxRetries     = 5
)

func init() {
	Register("notion", Connector{
		SourceType: sources.SourceNotion,
		Scan:       scanNotion,
		Verify:     verifyNotion,
	})
}

// scanNotion is the Lambda handler. cfg keys:
//   - token     (required) Bearer integration token
//   - api_base  override https://api.notion.com/v1
//   - query     filter the workspace search (empty → all accessible)
func scanNotion(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("notion: token is required (set --token or NOTION_TOKEN)")
	}
	apiBase := cfg.Get("api_base", notionDefaultAPIBase)
	query := cfg["query"]

	cli := newNotionClient(apiBase, token)
	nextCursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		body := map[string]any{"page_size": 100}
		if query != "" {
			body["query"] = query
		}
		if nextCursor != "" {
			body["start_cursor"] = nextCursor
		}
		bodyJSON, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("notion: marshal search body: %w", err)
		}
		var sr notionSearchResult
		if err := cli.postJSON(ctx, "/search", bodyJSON, &sr); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("notion: search: %w", err)
		}

		for _, item := range sr.Results {
			if err := ctx.Err(); err != nil {
				return err
			}
			switch item.Object {
			case "page":
				if err := emitNotionPage(ctx, cli, item, emit); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			case "database":
				if err := emitNotionDatabaseRows(ctx, cli, item, emit); err != nil {
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

func verifyNotion(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", notionDefaultAPIBase)
	cli := newNotionClient(apiBase, secret)
	resp, err := cli.do(ctx, http.MethodGet, "/users/me", nil)
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

// --- internal types ---

type notionSearchResult struct {
	Object  string             `json:"object"`
	Results []notionSearchItem `json:"results"`
	Next    string             `json:"next_cursor"`
	HasMore bool               `json:"has_more"`
}

type notionSearchItem struct {
	Object string          `json:"object"`
	ID     string          `json:"id"`
	URL    string          `json:"url"`
	Title  json.RawMessage `json:"title,omitempty"`
}

type notionBlockChildrenResp struct {
	Results []json.RawMessage `json:"results"`
	Next    string            `json:"next_cursor"`
	HasMore bool              `json:"has_more"`
}

type notionDBQueryResult struct {
	Results []json.RawMessage `json:"results"`
	Next    string            `json:"next_cursor"`
	HasMore bool              `json:"has_more"`
}

func emitNotionPage(ctx context.Context, cli *notionClient, item notionSearchItem, emit Emit) error {
	var pageFull struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := cli.getJSON(ctx, "/pages/"+item.ID, &pageFull); err != nil {
		return fmt.Errorf("notion: get page %s: %w", item.ID, err)
	}

	title := notionExtractTitle(pageFull.Properties)
	blocks, err := notionFetchAllBlocks(ctx, cli, item.ID)
	if err != nil {
		return err
	}
	text := "# " + title + "\n\n" + markdown.ConvertBlocks(blocks)
	return emit([]byte(text), sources.Metadata{
		Notion: &sources.NotionMeta{
			PageID: item.ID,
			Title:  title,
			URL:    item.URL,
			Part:   "page",
		},
	})
}

func emitNotionDatabaseRows(ctx context.Context, cli *notionClient, item notionSearchItem, emit Emit) error {
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
		var qr notionDBQueryResult
		if err := cli.postJSON(ctx, path, bodyJSON, &qr); err != nil {
			return fmt.Errorf("notion: query database %s: %w", item.ID, err)
		}

		for _, row := range qr.Results {
			var pageObj struct {
				ID  string `json:"id"`
				URL string `json:"url"`
			}
			_ = json.Unmarshal(row, &pageObj)
			text := notionExtractRowText(row)
			if err := emit([]byte(text), sources.Metadata{
				Notion: &sources.NotionMeta{
					PageID:   pageObj.ID,
					Database: item.ID,
					URL:      pageObj.URL,
					Part:     "database_row:" + pageObj.ID,
				},
			}); err != nil {
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

func notionFetchAllBlocks(ctx context.Context, cli *notionClient, parentID string) ([]json.RawMessage, error) {
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
		var bcr notionBlockChildrenResp
		if err := cli.getJSON(ctx, path, &bcr); err != nil {
			return nil, fmt.Errorf("notion: get block children for %s: %w", parentID, err)
		}

		for _, raw := range bcr.Results {
			var b struct {
				HasChildren bool   `json:"has_children"`
				ID          string `json:"id"`
			}
			_ = json.Unmarshal(raw, &b)
			if b.HasChildren {
				children, err := notionFetchAllBlocks(ctx, cli, b.ID)
				if err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return nil, err
					}
				} else {
					raw = notionInjectChildren(raw, children)
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

func notionInjectChildren(blockJSON json.RawMessage, children []json.RawMessage) json.RawMessage {
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

func notionExtractTitle(properties map[string]json.RawMessage) string {
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

func notionExtractRowText(raw json.RawMessage) string {
	var row struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		return string(raw)
	}
	var lines []string
	for name, propRaw := range row.Properties {
		text := notionExtractPropertyValue(propRaw)
		if text != "" {
			lines = append(lines, name+": "+text)
		}
	}
	return strings.Join(lines, "\n")
}

func notionExtractPropertyValue(raw json.RawMessage) string {
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

// --- HTTP client ---

type notionClient struct {
	base  string
	token string
	http  *http.Client
}

func newNotionClient(base, token string) *notionClient {
	if base == "" {
		base = notionDefaultAPIBase
	}
	return &notionClient{
		base:  base,
		token: token,
		http:  &http.Client{Timeout: notionRequestTimeout},
	}
}

func (c *notionClient) do(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	for attempt := 0; attempt < notionMaxRetries; attempt++ {
		var bodyReader io.Reader
		if body != nil {
			bodyReader = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Notion-Version", notionVersion)
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := notionRetryAfter(resp)
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

// getJSON issues a GET and decodes a 2xx body into out. A non-2xx status
// is rejected with an error embedding a bounded body read, so a 4xx/5xx
// can never be silently decoded into a zero-finding (false-clean) scan.
func (c *notionClient) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// postJSON issues a POST and decodes a 2xx body into out, applying the
// same non-2xx rejection as getJSON.
func (c *notionClient) postJSON(ctx context.Context, path string, body []byte, out any) error {
	resp, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *notionClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

func notionRetryAfter(resp *http.Response) time.Duration {
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
