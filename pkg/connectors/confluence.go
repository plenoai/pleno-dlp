// Confluence connector. Single-file Lambda-handler shape.
//
// Surface: Confluence content search → emit one chunk per page body and
// one chunk per attached footer/inline comment. Storage-format XHTML
// bodies parse via the helper sub-package
// pkg/connectors/confluence/storage — auth + fetch + emit live here.
//
// Auth: Cloud sends Basic (email + API token) when the email field is
// populated. Data Center / Server uses PAT Bearer when email is empty.
// Mirrors the Jira split — same Atlassian credentials apply to both.
//
// Pagination: Confluence content APIs return `_links.next` (relative)
// alongside `start`/`limit`/`size`. Following _links.next ends at the
// first response that omits the field.

package connectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/connectors/confluence/storage"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	confluenceRequestTimeout = 60 * time.Second
	confluencePageSize       = 50
)

func init() {
	Register("confluence", Connector{
		SourceType:  sources.SourceConfluence,
		Scan:        scanConfluence,
		Verify:      verifyConfluence,
		Fingerprint: fingerprintConfluence,
	})
}

// scanConfluence is the Lambda handler. cfg keys:
//   - token       (required) Cloud API token or Data Center PAT
//   - email       Atlassian account email; presence selects Basic auth (Cloud)
//   - api_base    (required) Confluence REST root (e.g. https://acme.atlassian.net/wiki)
//   - space       optional space key filter
func scanConfluence(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("confluence: token is required")
	}
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return errors.New("confluence: api_base is required")
	}
	cli := newConfluenceClient(apiBase, cfg["email"], token)
	previousState, err := loadConfluenceIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &confluenceIncrementalState{Version: 1, Objects: map[string]confluenceObjectIncrementalState{}}
	if previousState == nil {
		previousState = &confluenceIncrementalState{Version: 1, Objects: map[string]confluenceObjectIncrementalState{}}
	}
	scanState := confluenceScanState{previous: previousState, next: nextState}

	next := fmt.Sprintf("/rest/api/content?type=page&limit=%d&expand=body.storage,space,version", confluencePageSize)
	if space := cfg["space"]; space != "" {
		next += "&spaceKey=" + space
	}
	for next != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		var resp confluenceContentResp
		if err := cli.getJSON(ctx, next, &resp); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("confluence: list content: %w", err)
		}
		for _, page := range resp.Results {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := emitConfluencePage(ctx, cli, apiBase, page, &scanState, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		next = resp.Links.Next
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("confluence: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return nil
}

func verifyConfluence(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return false, errors.New("confluence: api_base not set")
	}
	cli := newConfluenceClient(apiBase, cfg["email"], secret)
	// /rest/api/user/current is the documented self-identity endpoint.
	resp, err := cli.do(ctx, http.MethodGet, "/rest/api/user/current", nil)
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
		return false, fmt.Errorf("confluence: verify unexpected status %s", resp.Status)
	}
}

func fingerprintConfluence(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", errors.New("confluence: token is required")
	}
	apiBase := strings.TrimRight(cfg["api_base"], "/")
	if apiBase == "" {
		return "", errors.New("confluence: api_base is required")
	}
	cli := newConfluenceClient(apiBase, cfg["email"], token)
	h := sha256.New()
	writeFingerprint(h, "confluence-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, cfg["space"])

	next := fmt.Sprintf("/rest/api/content?type=page&limit=%d&expand=body.storage,space,version", confluencePageSize)
	if space := cfg["space"]; space != "" {
		next += "&spaceKey=" + space
	}
	for next != "" {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		var resp confluenceContentResp
		if err := cli.getJSON(ctx, next, &resp); err != nil {
			return "", fmt.Errorf("confluence: list content: %w", err)
		}
		for _, page := range resp.Results {
			fingerprintConfluencePage(ctx, h, cli, page)
		}
		next = resp.Links.Next
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintConfluencePage(ctx context.Context, h hash.Hash, cli *confluenceClient, page confluencePage) {
	writeFingerprint(h, confluenceObjectKey(page.ID, "page"))
	writeFingerprint(h, page.Title)
	writeFingerprint(h, page.Body.Storage.Value)
	for _, location := range []string{"footer", "inline"} {
		next := fmt.Sprintf("/rest/api/content/%s/child/comment?location=%s&limit=%d&expand=body.storage,extensions.location",
			page.ID, location, confluencePageSize)
		for next != "" {
			var cresp confluenceCommentsResp
			if err := cli.getJSON(ctx, next, &cresp); err != nil {
				break
			}
			for _, com := range cresp.Results {
				writeFingerprint(h, confluenceObjectKey(page.ID, location+"-comment:"+com.ID))
				writeFingerprint(h, com.Body.Storage.Value)
			}
			next = cresp.Links.Next
		}
	}
}

// --- internal types ---

type confluenceContentResp struct {
	Results []confluencePage `json:"results"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type confluencePage struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Title string `json:"title"`
	Space struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"space"`
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Links struct {
		WebUI string `json:"webui"`
	} `json:"_links"`
}

type confluenceCommentsResp struct {
	Results []confluenceComment `json:"results"`
	Links   struct {
		Next string `json:"next"`
	} `json:"_links"`
}

type confluenceComment struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Body struct {
		Storage struct {
			Value string `json:"value"`
		} `json:"storage"`
	} `json:"body"`
	Extensions struct {
		Location string `json:"location"`
	} `json:"extensions"`
}

type confluenceIncrementalState struct {
	Version int                                         `json:"version"`
	Objects map[string]confluenceObjectIncrementalState `json:"objects"`
}

type confluenceObjectIncrementalState struct {
	Hash string `json:"hash,omitempty"`
}

type confluenceScanState struct {
	previous *confluenceIncrementalState
	next     *confluenceIncrementalState
}

func loadConfluenceIncrementalState(raw string) (*confluenceIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state confluenceIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("confluence: parse incremental source state: %w", err)
	}
	if state.Objects == nil {
		state.Objects = map[string]confluenceObjectIncrementalState{}
	}
	return &state, nil
}

func emitConfluencePage(ctx context.Context, cli *confluenceClient, apiBase string, page confluencePage, state *confluenceScanState, emit Emit) error {
	if v := page.Body.Storage.Value; v != "" {
		key := confluenceObjectKey(page.ID, "page")
		current := confluenceStateForText(page.Title + "\x00" + v)
		if state != nil && state.next != nil {
			state.next.Objects[key] = current
		}
		if state == nil || state.previous == nil || state.previous.Objects[key] != current {
			text := storage.ToText(v)
			if text == "" {
				text = v
			}
			if err := emit([]byte("# "+page.Title+"\n\n"+text), sources.Metadata{
				Confluence: &sources.ConfluenceMeta{
					SpaceKey:  page.Space.Key,
					SpaceName: page.Space.Name,
					PageID:    page.ID,
					Title:     page.Title,
					URL:       apiBase + page.Links.WebUI,
					Type:      "page",
				},
			}); err != nil {
				return err
			}
		}
	}
	// Walk footer + inline comments. Per-comment errors are tolerated.
	for _, location := range []string{"footer", "inline"} {
		next := fmt.Sprintf("/rest/api/content/%s/child/comment?location=%s&limit=%d&expand=body.storage,extensions.location",
			page.ID, location, confluencePageSize)
		for next != "" {
			if err := ctx.Err(); err != nil {
				return err
			}
			var cresp confluenceCommentsResp
			if err := cli.getJSON(ctx, next, &cresp); err != nil {
				break
			}
			for _, com := range cresp.Results {
				v := com.Body.Storage.Value
				if v == "" {
					continue
				}
				partType := location + "-comment"
				key := confluenceObjectKey(page.ID, partType+":"+com.ID)
				current := confluenceStateForText(v)
				if state != nil && state.next != nil {
					state.next.Objects[key] = current
				}
				if state != nil && state.previous != nil && state.previous.Objects[key] == current {
					continue
				}
				text := storage.ToText(v)
				if text == "" {
					text = v
				}
				if err := emit([]byte(text), sources.Metadata{
					Confluence: &sources.ConfluenceMeta{
						SpaceKey:  page.Space.Key,
						SpaceName: page.Space.Name,
						PageID:    page.ID,
						Title:     page.Title,
						URL:       apiBase + page.Links.WebUI,
						Type:      partType,
					},
				}); err != nil {
					return err
				}
			}
			next = cresp.Links.Next
		}
	}
	return nil
}

func confluenceObjectKey(pageID, part string) string {
	return pageID + ":" + part
}

func confluenceStateForText(text string) confluenceObjectIncrementalState {
	sum := sha256.Sum256([]byte(text))
	return confluenceObjectIncrementalState{Hash: hex.EncodeToString(sum[:])}
}

// --- HTTP client ---

type confluenceClient struct {
	base  string
	email string
	token string
	http  *http.Client
}

func newConfluenceClient(base, email, token string) *confluenceClient {
	return &confluenceClient{
		base:  base,
		email: email,
		token: token,
		http:  &http.Client{Timeout: confluenceRequestTimeout},
	}
}

func (c *confluenceClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	url := path
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		if !strings.HasPrefix(url, "/") {
			url = "/" + url
		}
		url = c.base + url
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if c.email != "" {
		req.SetBasicAuth(c.email, c.token)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return c.http.Do(req)
}

func (c *confluenceClient) getJSON(ctx context.Context, path string, out any) error {
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
