// Slack connector. Single-file Lambda-handler shape.
//
// Surface: conversations.list to discover channels, conversations.history
// per channel for messages, conversations.replies for threaded parents,
// files.info + url_private_download for attached files. When the channel
// config key is set, listing is skipped and only that channel is scanned.
//
// Auth: Bot (`xoxb-`) or User (`xoxp-`) token sent as Authorization: Bearer.
// Verify hits POST /api/auth.test and reads `ok: true`.
//
// Pagination: cursor pagination via response_metadata.next_cursor +
// has_more across all list/history/replies endpoints.

package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	slackDefaultAPIBase  = "https://slack.com/api"
	slackRequestTimeout  = 60 * time.Second
	slackMaxDownloadSize = 50 << 20
)

func init() {
	Register("slack", Connector{
		SourceType: sources.SourceSlack,
		Scan:       scanSlack,
		Verify:     verifySlack,
	})
}

// slackWarn surfaces a non-fatal diagnostic. The package has no logger, so
// warnings go to stderr by default; tests swap this var to capture them.
// It exists so a single bad thread (auth/rate/decode error) is visible
// instead of being silently reported as zero findings.
var slackWarn = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "slack: warning: "+format+"\n", args...)
}

// scanSlack is the Lambda handler. cfg keys:
//   - token       (required) `xoxb-` or `xoxp-` token
//   - channel     single channel ID (omit to list all)
//   - api_base    override https://slack.com/api
//   - concurrency thread-reply fanout
func scanSlack(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("slack: token is required (set --token or SLACK_TOKEN)")
	}
	apiBase := cfg.Get("api_base", slackDefaultAPIBase)
	concurrency := 4
	if v := cfg["concurrency"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			concurrency = n
		}
	}

	cli := newSlackClient(apiBase, token)
	channels, err := slackResolveChannels(ctx, cli, cfg["channel"])
	if err != nil {
		return err
	}
	for _, ch := range channels {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanSlackChannel(ctx, cli, ch, concurrency, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			continue
		}
	}
	return nil
}

func verifySlack(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", slackDefaultAPIBase)
	cli := newSlackClient(apiBase, secret)
	resp, err := cli.do(ctx, http.MethodPost, "/api/auth.test", nil)
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

// --- internal types ---

type slackChannelInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type slackMessage struct {
	Text      string `json:"text"`
	TS        string `json:"ts"`
	ThreadTS  string `json:"thread_ts"`
	Permalink string `json:"permalink"`
	Files     []struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		URLPrivateDownload string `json:"url_private_download"`
	} `json:"files"`
}

type slackConvListResp struct {
	OK               bool               `json:"ok"`
	Error            string             `json:"error"`
	Channels         []slackChannelInfo `json:"channels"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

type slackConvHistoryResp struct {
	OK               bool           `json:"ok"`
	Error            string         `json:"error"`
	Messages         []slackMessage `json:"messages"`
	HasMore          bool           `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

type slackConvRepliesResp struct {
	OK               bool           `json:"ok"`
	Error            string         `json:"error"`
	Messages         []slackMessage `json:"messages"`
	HasMore          bool           `json:"has_more"`
	ResponseMetadata struct {
		NextCursor string `json:"next_cursor"`
	} `json:"response_metadata"`
}

type slackFilesInfoResp struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
	File  struct {
		ID                 string `json:"id"`
		Name               string `json:"name"`
		URLPrivateDownload string `json:"url_private_download"`
	} `json:"file"`
}

func slackResolveChannels(ctx context.Context, cli *slackClient, single string) ([]slackChannelInfo, error) {
	if single != "" {
		return []slackChannelInfo{{ID: single}}, nil
	}
	var channels []slackChannelInfo
	cursor := ""
	for {
		path := "/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200"
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp slackConvListResp
		if err := cli.getJSON(ctx, path, &resp); err != nil {
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

func scanSlackChannel(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, concurrency int, emit Emit) error {
	cursor := ""
	for {
		path := fmt.Sprintf("/api/conversations.history?channel=%s&limit=200", chInfo.ID)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp slackConvHistoryResp
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return fmt.Errorf("slack: history channel=%s: %w", chInfo.ID, err)
		}
		if !resp.OK {
			return fmt.Errorf("slack: history channel=%s: %s", chInfo.ID, resp.Error)
		}
		g, gctx := errgroup.WithContext(ctx)
		sem := make(chan struct{}, concurrency)
		for i := range resp.Messages {
			msg := resp.Messages[i]
			if err := emitSlackMessage(ctx, chInfo, msg, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
			for _, f := range msg.Files {
				if err := emitSlackFile(ctx, cli, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, emit); err != nil {
					if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
						return err
					}
					continue
				}
			}
			if msg.ThreadTS != "" && msg.ThreadTS == msg.TS {
				select {
				case sem <- struct{}{}:
				case <-gctx.Done():
					return gctx.Err()
				}
				parent := msg
				g.Go(func() error {
					defer func() { <-sem }()
					return scanSlackThread(gctx, cli, chInfo, parent, emit)
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

func scanSlackThread(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, parent slackMessage, emit Emit) error {
	cursor := ""
	for {
		path := fmt.Sprintf("/api/conversations.replies?channel=%s&ts=%s&limit=200", chInfo.ID, parent.ThreadTS)
		if cursor != "" {
			path += "&cursor=" + cursor
		}
		var resp slackConvRepliesResp
		if err := cli.getJSON(ctx, path, &resp); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			// Log-and-continue: do not propagate. scanSlackThread runs in an
			// errgroup whose g.Wait() would cancel the whole channel scan on
			// one bad thread. Surfacing the error prevents a thread with an
			// auth/rate/decode failure from masquerading as zero findings.
			slackWarn("channel=%s thread=%s replies fetch failed: %v", chInfo.ID, parent.ThreadTS, err)
			return nil
		}
		if !resp.OK {
			slackWarn("channel=%s thread=%s conversations.replies not ok: %s", chInfo.ID, parent.ThreadTS, resp.Error)
			return nil
		}
		for _, msg := range resp.Messages {
			if msg.TS == parent.TS {
				continue
			}
			if err := emitSlackMessage(ctx, chInfo, msg, emit); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
			for _, f := range msg.Files {
				if err := emitSlackFile(ctx, cli, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, emit); err != nil {
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

func emitSlackMessage(_ context.Context, chInfo slackChannelInfo, msg slackMessage, emit Emit) error {
	if msg.Text == "" {
		return nil
	}
	return emit([]byte(msg.Text), sources.Metadata{
		Slack: &sources.SlackMeta{
			Channel:   chInfo.ID,
			Timestamp: msg.TS,
			Permalink: msg.Permalink,
		},
	})
}

func emitSlackFile(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, msg slackMessage, fileID, fileName, downloadURL string, emit Emit) error {
	if downloadURL == "" {
		var resp slackFilesInfoResp
		if err := cli.getJSON(ctx, "/api/files.info?file="+fileID, &resp); err != nil {
			return nil
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
	data, err := cli.download(ctx, downloadURL)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	return emit(data, sources.Metadata{
		Slack: &sources.SlackMeta{
			Channel:   chInfo.ID,
			Timestamp: msg.TS,
			Permalink: fileName,
		},
	})
}

// --- HTTP client ---

type slackClient struct {
	base  string
	token string
	http  *http.Client

	mu          sync.Mutex
	nextAllowed time.Time

	testSleep func(time.Duration)
}

func newSlackClient(base, token string) *slackClient {
	if base == "" {
		base = slackDefaultAPIBase
	}
	return &slackClient{
		base:  base,
		token: token,
		http:  &http.Client{Timeout: slackRequestTimeout},
	}
}

func (c *slackClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
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

func (c *slackClient) getJSON(ctx context.Context, path string, out any) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
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

func (c *slackClient) download(ctx context.Context, url string) ([]byte, error) {
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
	return io.ReadAll(io.LimitReader(resp.Body, slackMaxDownloadSize))
}

func (c *slackClient) url(p string) string {
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(c.base, "/") + p
}

func (c *slackClient) waitForBucket(ctx context.Context) error {
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
