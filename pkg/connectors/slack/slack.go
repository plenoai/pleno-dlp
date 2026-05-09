// Package slack is the SaaSConnector port for Slack workspaces.
//
// It satisfies sources.Source so the engine drives a Slack scan with the
// exact same loop it uses for filesystem / git / stdin (Init, Chunks, Type),
// plus connectors.SaaSConnector via Descriptor() and detectors.Verifier via
// Verify() — wired up per ADR-0001 (D1 / D4 / D5).
//
// Scope:
//
//   - Auth: Bot token (xoxb-), User token (xoxp-). Sent as Bearer header.
//   - Source surface: conversations.list to discover channels,
//     conversations.history per channel for messages, conversations.replies
//     for thread parents, and files.info + url_private_download for file
//     content. If --channel is set, listing is skipped.
//   - Verify: POST /api/auth.test. ok:true → verified.
//   - Rate limit: Slack Tier 1-4 rate limits. Parse Retry-After on 429.
//
// Concurrency: channels are walked sequentially; thread reply fetches are
// fanned out under a semaphore of size `concurrency`. The connector honours
// ctx.Done() at every send and every API call so cancellation propagates.
package slack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/connectors"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// DefaultAPIBase is the public Slack API root. No override hook exists for
// on-prem Slack — the SaaS API is the only target.
const DefaultAPIBase = "https://slack.com/api"

// requestTimeout caps a single REST call. Channel histories can be deep;
// the surrounding ctx is the real cancellation signal.
const requestTimeout = 60 * time.Second

func init() {
	connectors.Register("slack", func() connectors.SaaSConnector { return &Connector{} })
	sources.Register(sources.SourceSlack, func() sources.Source { return &Connector{} })
}

// Config is the JSON shape Init expects. The CLI builds it from --token /
// --channel and a SLACK_TOKEN env-var fallback.
type Config struct {
	// Token is a Slack Bot token (xoxb-...) or User token (xoxp-...), sent
	// as Authorization: Bearer <token>. Required for both scan and verify.
	Token string `json:"token"`
	// Channel scopes the scan to a single channel (by ID). When empty, the
	// connector discovers every channel the token can see via
	// conversations.list and scans them all.
	Channel string `json:"channel,omitempty"`
	// APIBase overrides the REST root. Defaults to https://slack.com/api.
	APIBase string `json:"api_base,omitempty"`
}

// Connector is the Slack SaaSConnector. One instance per scan: Init validates
// config, Chunks streams message+file bodies, Verify probes auth.test.
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
func (c *Connector) Type() sources.SourceType { return sources.SourceSlack }

// Descriptor returns the static metadata the CLI introspects.
func (c *Connector) Descriptor() connectors.Descriptor {
	return connectors.Descriptor{
		Name:       "slack",
		SourceType: sources.SourceSlack,
		AuthModes:  []connectors.AuthMode{connectors.AuthBearer},
		Capabilities: connectors.CapSource | connectors.CapVerify |
			connectors.CapRevoke,
	}
}

// Init parses the JSON config, validates auth, and wires up the
// rate-limit-aware HTTP client. Init MUST be called before Chunks.
func (c *Connector) Init(_ context.Context, name string, jobID, sourceID int64, verifyFlag bool, config []byte, concurrency int) error {
	var cfg Config
	if len(config) > 0 {
		if err := json.Unmarshal(config, &cfg); err != nil {
			return fmt.Errorf("slack: invalid config json: %w", err)
		}
	}
	if cfg.Token == "" {
		return errors.New("slack: config.token is required (set --token or SLACK_TOKEN)")
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

// Chunks walks every channel the token can see (or a single channel when
// Config.Channel is set), then emits one Chunk per message and per file.
// Per-channel failures (missing_scope, channel_not_found) are tolerated —
// we skip and continue. Only context cancellation propagates as an error.
func (c *Connector) Chunks(ctx context.Context, ch chan<- *sources.Chunk) error {
	channels, err := c.resolveChannels(ctx)
	if err != nil {
		return err
	}
	for _, chInfo := range channels {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := c.scanChannel(ctx, chInfo, ch); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Scope degrade: log and skip, do not abort.
			continue
		}
	}
	return nil
}

// Verify implements detectors.Verifier. POST /api/auth.test;
// ok:true → verified.
func (c *Connector) Verify(ctx context.Context, secret string) (bool, error) {
	base := c.cfg.APIBase
	if base == "" {
		base = DefaultAPIBase
	}
	cl := NewClient(base, secret, nil)
	resp, err := cl.Do(ctx, http.MethodPost, "/api/auth.test", nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	var result struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("slack: decode auth.test: %w", err)
	}
	return result.OK, nil
}

// Compile-time interface checks.
var (
	_ sources.Source           = (*Connector)(nil)
	_ connectors.SaaSConnector = (*Connector)(nil)
	_ connectors.Verifier      = (*Connector)(nil)
)

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

// channelInfo captures the subset of Slack's conversation object we need.
type channelInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// message captures the subset of Slack's message object we need.
type message struct {
	Text      string `json:"text"`
	TS        string `json:"ts"`
	ThreadTS  string `json:"thread_ts"`
	Permalink string `json:"permalink"`
	Files     []struct {
		ID    string `json:"id"`
		Name  string `json:"name"`
		URLPrivateDownload string `json:"url_private_download"`
	} `json:"files"`
}

// conversationsListResp is the Slack API response for conversations.list.
type conversationsListResp struct {
	OK               bool          `json:"ok"`
	Error            string        `json:"error"`
	Channels         []channelInfo `json:"channels"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// conversationsHistoryResp is the Slack API response for conversations.history.
type conversationsHistoryResp struct {
	OK               bool      `json:"ok"`
	Error            string    `json:"error"`
	Messages         []message `json:"messages"`
	HasMore          bool      `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// conversationsRepliesResp is the Slack API response for conversations.replies.
type conversationsRepliesResp struct {
	OK       bool      `json:"ok"`
	Error    string    `json:"error"`
	Messages []message `json:"messages"`
	HasMore  bool      `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

// filesInfoResp is the Slack API response for files.info.
type filesInfoResp struct {
	OK    bool `json:"ok"`
	Error string `json:"error"`
	File  struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		URLPrivateDownload string `json:"url_private_download"`
	} `json:"file"`
}

// ---------------------------------------------------------------------------
// Channel resolution
// ---------------------------------------------------------------------------

// resolveChannels returns a list of channels to scan. When Config.Channel
// is set, it returns that single channel (fetched via conversations.info
// so we have the name). Otherwise it pages through conversations.list.
func (c *Connector) resolveChannels(ctx context.Context) ([]channelInfo, error) {
	if c.cfg.Channel != "" {
		// Single channel mode: return the channel ID as-is. We fill the
		// name lazily during the scan; the ID is sufficient for
		// conversations.history.
		return []channelInfo{{ID: c.cfg.Channel}}, nil
	}
	var channels []channelInfo
	cursor := ""
	for {
		path := "/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp conversationsListResp
		if err := c.client.GetJSON(ctx, path, &resp); err != nil {
			return nil, fmt.Errorf("slack: list conversations: %w", err)
		}
		if !resp.OK {
			return nil, fmt.Errorf("slack: conversations.list: %s", resp.Error)
		}
		channels = append(channels, resp.Channels...)
		cursor = resp.ResponseMetadata.NextCursor
		if cursor == "" {
			break
		}
	}
	return channels, nil
}

// ---------------------------------------------------------------------------
// Channel scanning
// ---------------------------------------------------------------------------

// scanChannel pages through conversations.history for a single channel,
// emitting one Chunk per message and per file. Thread replies are fetched
// in a fan-out goroutine pool.
func (c *Connector) scanChannel(ctx context.Context, chInfo channelInfo, ch chan<- *sources.Chunk) error {
	cursor := ""
	for {
		path := fmt.Sprintf("/api/conversations.history?channel=%s&limit=200", chInfo.ID)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp conversationsHistoryResp
		if err := c.client.GetJSON(ctx, path, &resp); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("slack: history channel=%s: %w", chInfo.ID, err)
		}
		if !resp.OK {
			// Scope degrade: missing_scope, channel_not_found, etc.
			// Return a non-nil, non-context error so Chunks skips.
			return fmt.Errorf("slack: history channel=%s: %s", chInfo.ID, resp.Error)
		}
		// Fan out thread reply fetches within this page.
		g, gctx := errgroup.WithContext(ctx)
		sem := make(chan struct{}, c.concurrency)
		for i := range resp.Messages {
			msg := resp.Messages[i]
			// Emit the message itself.
			if err := c.emitMessage(ctx, chInfo, msg, ch); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
			// Emit files attached to this message.
			for _, f := range msg.Files {
				if err := c.emitFile(ctx, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, ch); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			}
			// Thread parent: fetch replies in a goroutine. In Slack's
			// API, a parent message has thread_ts == ts. Replies
			// have thread_ts != ts and don't appear in history.
			if msg.ThreadTS != "" && msg.ThreadTS == msg.TS {
				select {
				case sem <- struct{}{}:
				case <-gctx.Done():
					return g.Wait()
				}
				g.Go(func() error {
					defer func() { <-sem }()
					return c.scanThread(gctx, chInfo, msg, ch)
				})
			}
		}
		if err := g.Wait(); err != nil {
			return err
		}
		cursor = resp.ResponseMetadata.NextCursor
		if !resp.HasMore || cursor == "" {
			break
		}
	}
	return nil
}

// scanThread pages through conversations.replies for a single thread.
func (c *Connector) scanThread(ctx context.Context, chInfo channelInfo, parent message, ch chan<- *sources.Chunk) error {
	cursor := ""
	for {
		path := fmt.Sprintf("/api/conversations.replies?channel=%s&ts=%s&limit=200", chInfo.ID, parent.ThreadTS)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp conversationsRepliesResp
		if err := c.client.GetJSON(ctx, path, &resp); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return nil // swallow per-thread errors
		}
		if !resp.OK {
			return nil // swallow scope-degrade per thread
		}
		for _, msg := range resp.Messages {
			// Skip the parent message — it was already emitted from
			// conversations.history.
			if msg.TS == parent.TS {
				continue
			}
			if err := c.emitMessage(ctx, chInfo, msg, ch); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
			for _, f := range msg.Files {
				if err := c.emitFile(ctx, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, ch); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			}
		}
		cursor = resp.ResponseMetadata.NextCursor
		if !resp.HasMore || cursor == "" {
			break
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Chunk emission helpers
// ---------------------------------------------------------------------------

// emitMessage pushes one Chunk for a message body.
func (c *Connector) emitMessage(ctx context.Context, chInfo channelInfo, msg message, ch chan<- *sources.Chunk) error {
	if msg.Text == "" {
		return nil
	}
	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceSlack,
		SourceName: c.name,
		Data:       []byte(msg.Text),
		SourceMetadata: sources.Metadata{
			Slack: &sources.SlackMeta{
				Channel:   chInfo.ID,
				Timestamp: msg.TS,
				Permalink: msg.Permalink,
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

// emitFile fetches file metadata via files.info (if url_private_download
// is empty), downloads the file content, and pushes one Chunk.
func (c *Connector) emitFile(ctx context.Context, chInfo channelInfo, msg message, fileID, fileName, downloadURL string, ch chan<- *sources.Chunk) error {
	if downloadURL == "" {
		// Fetch file metadata to get the download URL.
		var resp filesInfoResp
		if err := c.client.GetJSON(ctx, "/api/files.info?file="+fileID, &resp); err != nil {
			return nil // swallow per-file errors
		}
		if !resp.OK {
			return nil
		}
		downloadURL = resp.File.URLPrivateDownload
		fileName = resp.File.Name
	}
	if downloadURL == "" {
		return nil
	}
	data, err := c.client.Download(ctx, downloadURL)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil // swallow per-file download errors
	}
	chunk := &sources.Chunk{
		SourceID:   c.sourceID,
		SourceType: sources.SourceSlack,
		SourceName: c.name,
		Data:       data,
		SourceMetadata: sources.Metadata{
			Slack: &sources.SlackMeta{
				Channel:   chInfo.ID,
				Timestamp: msg.TS,
				Permalink: fileName,
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

// ---------------------------------------------------------------------------
// HTTP Client (rate-limit aware)
// ---------------------------------------------------------------------------

// Client is a small, rate-limit-aware Slack REST client. It parses the
// Retry-After header on 429 responses and backs off exponentially.
type Client struct {
	base  string
	token string
	http  *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	// testSleep, when non-nil, replaces real sleeps during retry backoff.
	testSleep func(time.Duration)
}

// NewClient constructs a Client. httpClient may be nil — a bounded-timeout
// default is installed so a wedged Slack doesn't pin the whole scan.
func NewClient(base, token string, httpClient *http.Client) *Client {
	if base == "" {
		base = DefaultAPIBase
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: requestTimeout}
	}
	return &Client{base: base, token: token, http: httpClient}
}

// Do issues an HTTP request against the Slack API. It retries on 429
// (up to 5 attempts), honouring Retry-After for the wait duration.
// Callers MUST close resp.Body.
func (c *Client) Do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.url(path), body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			wait := slackBackoff(resp, attempt)
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if c.testSleep != nil {
				c.testSleep(wait)
				continue
			}
			if wait <= 0 {
				wait = time.Second
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
	return nil, errors.New("slack: exhausted retries against rate limit")
}

// GetJSON issues a GET and decodes a JSON body into out. The response body
// is drained and closed. Slack returns {"ok":false,"error":"..."} on API
// errors — the caller inspects the ok/error fields.
func (c *Client) GetJSON(ctx context.Context, path string, out any) error {
	resp, err := c.Do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("slack: GET %s -> %s: %s", path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("slack: decode %s: %w", path, err)
		}
	}
	return nil
}

// Download fetches a file by absolute URL (url_private_download). Returns
// the raw bytes. Bounded to 50 MiB to avoid OOM on huge uploads.
func (c *Client) Download(ctx context.Context, url string) ([]byte, error) {
	const maxDownload = 50 << 20
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("slack: download %s -> %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxDownload))
}

// url returns the absolute URL to request.
func (c *Client) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

// waitForBucket blocks until the rate-limit bucket allows another call.
func (c *Client) waitForBucket(ctx context.Context) error {
	c.mu.Lock()
	until := c.nextAllowed
	c.mu.Unlock()
	if until.IsZero() {
		return nil
	}
	delay := time.Until(until)
	if delay <= 0 {
		return nil
	}
	if c.testSleep != nil {
		c.testSleep(delay)
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
		return nil
	}
}

// slackBackoff extracts Retry-After from a 429 response, falling back to
// exponential backoff capped at a minute.
func slackBackoff(resp *http.Response, attempt int) time.Duration {
	if v := resp.Header.Get("Retry-After"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs >= 0 {
			return time.Duration(secs * float64(time.Second))
		}
	}
	d := time.Duration(1<<attempt) * time.Second
	if d > time.Minute {
		d = time.Minute
	}
	return d
}
