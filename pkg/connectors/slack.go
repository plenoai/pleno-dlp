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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/plenoai/pleno-dlp/pkg/termsafe"
	"hash"
	"io"
	"net/http"
	neturl "net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

const (
	// slackDefaultAPIBase is the host root, NOT the /api path: every
	// request path in this file already carries its own `/api/` prefix
	// (the real Slack Web API endpoints, e.g. `/api/auth.test`). Keeping
	// `/api` here as well produced `https://slack.com/api/api/auth.test`,
	// so scan/verify never reached Slack. newSlackClient additionally
	// strips a trailing `/api` from any configured base for the same
	// reason.
	slackDefaultAPIBase  = "https://slack.com"
	slackRequestTimeout  = 60 * time.Second
	slackMaxDownloadSize = 50 << 20
)

func init() {
	Register("slack", Connector{
		SourceType:  sources.SourceSlack,
		Scan:        scanSlack,
		Verify:      verifySlack,
		Fingerprint: fingerprintSlack,
	})
}

// slackWarn surfaces a non-fatal diagnostic. The package has no logger, so
// warnings go to stderr by default; tests swap this var to capture them.
// It exists so a single bad thread (auth/rate/decode error) is visible
// instead of being silently reported as zero findings.
var slackWarn = func(format string, args ...any) {
	termsafe.Fprintf(os.Stderr, "slack: warning: "+format+"\n", args...)
}

// scanSlack is the Lambda handler. cfg keys:
//   - token       (required) `xoxb-` or `xoxp-` token
//   - channel     single channel ID (omit to list all)
//   - api_base    override host root, e.g. https://slack.com (a trailing /api is tolerated)
//   - concurrency thread-reply fanout
func scanSlack(ctx context.Context, cfg Config, emit Emit) error {
	token := cfg["token"]
	if token == "" {
		return errors.New("slack: token is required (set --token or SLACK_TOKEN)")
	}
	apiBase := cfg.Get("api_base", slackDefaultAPIBase)
	if err := requireSecureEndpoint("slack", apiBase); err != nil {
		return err
	}
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
	previousState, err := loadSlackIncrementalState(cfg[configKeyIncrementalPreviousState])
	if err != nil {
		return err
	}
	nextState := &slackIncrementalState{Version: 1, Messages: map[string]slackMessageIncrementalState{}, Files: map[string]slackFileIncrementalState{}}
	if previousState == nil {
		previousState = &slackIncrementalState{Version: 1, Messages: map[string]slackMessageIncrementalState{}, Files: map[string]slackFileIncrementalState{}}
	}
	scanState := slackScanState{previous: previousState, next: nextState}
	for _, ch := range channels {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := scanSlackChannel(ctx, cli, ch, concurrency, &scanState, emit); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			scanState.fail("slack/"+ch.ID, err)
		}
	}
	data, err := json.Marshal(nextState)
	if err != nil {
		return fmt.Errorf("slack: encode incremental source state: %w", err)
	}
	cfg[configKeyIncrementalNextState] = string(data)
	return scanState.degraded()
}

func verifySlack(ctx context.Context, cfg Config, secret string) (bool, error) {
	apiBase := cfg.Get("api_base", slackDefaultAPIBase)
	if err := requireSecureEndpoint("slack", apiBase); err != nil {
		return false, err
	}
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

func fingerprintSlack(ctx context.Context, cfg Config) (string, error) {
	token := cfg["token"]
	if token == "" {
		return "", errors.New("slack: token is required (set --token or SLACK_TOKEN)")
	}
	apiBase := cfg.Get("api_base", slackDefaultAPIBase)
	if err := requireSecureEndpoint("slack", apiBase); err != nil {
		return "", err
	}
	cli := newSlackClient(apiBase, token)
	channels, err := slackResolveChannels(ctx, cli, cfg["channel"])
	if err != nil {
		return "", err
	}
	h := sha256.New()
	writeFingerprint(h, "slack-v1")
	writeFingerprint(h, apiBase)
	writeFingerprint(h, cfg["channel"])
	for _, ch := range channels {
		if err := fingerprintSlackChannel(ctx, h, cli, ch); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func fingerprintSlackChannel(ctx context.Context, h hash.Hash, cli *slackClient, chInfo slackChannelInfo) error {
	writeFingerprint(h, chInfo.ID)
	// A thread whose replies could not be read must not yield a stable
	// fingerprint, or an unchanged-source skip would hide the gap.
	var gaps slackScanState
	err := scanSlackChannelMessages(ctx, cli, chInfo, func(msg slackMessage) error {
		fingerprintSlackMessage(h, chInfo, msg)
		if msg.ThreadTS != "" && msg.ThreadTS == msg.TS {
			return scanSlackThreadMessages(ctx, cli, chInfo, msg, &gaps, func(reply slackMessage) error {
				if reply.TS == msg.TS {
					return nil
				}
				fingerprintSlackMessage(h, chInfo, reply)
				return nil
			})
		}
		return nil
	})
	if err != nil {
		return err
	}
	return gaps.degraded()
}

func fingerprintSlackMessage(h hash.Hash, chInfo slackChannelInfo, msg slackMessage) {
	writeFingerprint(h, "message")
	writeFingerprint(h, chInfo.ID)
	writeFingerprint(h, msg.TS)
	writeFingerprint(h, msg.Text)
	for _, f := range msg.Files {
		writeFingerprint(h, "file")
		writeFingerprint(h, f.ID)
		writeFingerprint(h, f.Name)
		writeFingerprint(h, f.URLPrivateDownload)
	}
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

type slackIncrementalState struct {
	Version  int                                     `json:"version"`
	Messages map[string]slackMessageIncrementalState `json:"messages"`
	Files    map[string]slackFileIncrementalState    `json:"files"`
}

type slackMessageIncrementalState struct {
	Text string `json:"text,omitempty"`
}

type slackFileIncrementalState struct {
	Name               string `json:"name,omitempty"`
	URLPrivateDownload string `json:"url_private_download,omitempty"`
}

type slackScanState struct {
	previous *slackIncrementalState
	next     *slackIncrementalState

	// Per-channel, per-thread and per-file fetch failures (auth, rate
	// limit, cross-origin download refusal, oversize body) are coverage
	// gaps surfaced as engine.DegradedError, never silent zero findings
	// (#882). Thread scans run concurrently, hence the mutex.
	mu       sync.Mutex
	failures []engine.ScanFailure
}

// fail records a coverage gap. It is nil-safe so helpers can be driven
// without incremental state in tests; the warning is always emitted.
func (s *slackScanState) fail(source string, err error) {
	slackWarn("%s: %v", source, err)
	if s == nil {
		return
	}
	s.mu.Lock()
	s.failures = append(s.failures, engine.ScanFailure{Kind: engine.FailureSource, Source: source, Err: err})
	s.mu.Unlock()
}

func (s *slackScanState) degraded() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.failures) == 0 {
		return nil
	}
	failures := append([]engine.ScanFailure(nil), s.failures...)
	return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
}

func loadSlackIncrementalState(raw string) (*slackIncrementalState, error) {
	if raw == "" {
		return nil, nil
	}
	var state slackIncrementalState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return nil, fmt.Errorf("slack: parse incremental source state: %w", err)
	}
	if state.Messages == nil {
		state.Messages = map[string]slackMessageIncrementalState{}
	}
	if state.Files == nil {
		state.Files = map[string]slackFileIncrementalState{}
	}
	return &state, nil
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

func scanSlackChannel(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, concurrency int, state *slackScanState, emit Emit) error {
	return scanSlackChannelMessages(ctx, cli, chInfo, func(msg slackMessage) error {
		if err := emitSlackMessageIncremental(ctx, chInfo, msg, state, emit); err != nil {
			return err
		}
		for _, f := range msg.Files {
			if err := emitSlackFileIncremental(ctx, cli, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, state, emit); err != nil {
				return err
			}
		}
		if msg.ThreadTS != "" && msg.ThreadTS == msg.TS {
			return scanSlackThreadConcurrent(ctx, cli, chInfo, msg, concurrency, state, emit)
		}
		return nil
	})
}

func scanSlackChannelMessages(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, visit func(slackMessage) error) error {
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
		for i := range resp.Messages {
			if err := visit(resp.Messages[i]); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		cursor = resp.ResponseMetadata.NextCursor
		if !resp.HasMore || cursor == "" {
			break
		}
	}
	return nil
}

func scanSlackThreadConcurrent(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, parent slackMessage, concurrency int, state *slackScanState, emit Emit) error {
	g, gctx := errgroup.WithContext(ctx)
	sem := make(chan struct{}, concurrency)
	select {
	case sem <- struct{}{}:
	case <-gctx.Done():
		return gctx.Err()
	}
	g.Go(func() error {
		defer func() { <-sem }()
		return scanSlackThread(gctx, cli, chInfo, parent, state, emit)
	})
	return g.Wait()
}

func scanSlackThread(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, parent slackMessage, state *slackScanState, emit Emit) error {
	return scanSlackThreadMessages(ctx, cli, chInfo, parent, state, func(msg slackMessage) error {
		if msg.TS == parent.TS {
			return nil
		}
		if err := emitSlackMessageIncremental(ctx, chInfo, msg, state, emit); err != nil {
			return err
		}
		for _, f := range msg.Files {
			if err := emitSlackFileIncremental(ctx, cli, chInfo, msg, f.ID, f.Name, f.URLPrivateDownload, state, emit); err != nil {
				return err
			}
		}
		return nil
	})
}

func slackThreadSource(channel, ts string) string {
	return "slack/" + channel + "/thread/" + ts
}

func scanSlackThreadMessages(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, parent slackMessage, state *slackScanState, visit func(slackMessage) error) error {
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
			// Record-and-continue: do not propagate. scanSlackThread runs in
			// an errgroup whose g.Wait() would cancel the whole channel scan
			// on one bad thread; the gap is recorded as a coverage failure.
			state.fail(slackThreadSource(chInfo.ID, parent.ThreadTS), fmt.Errorf("replies fetch failed: %w", err))
			return nil
		}
		if !resp.OK {
			state.fail(slackThreadSource(chInfo.ID, parent.ThreadTS), fmt.Errorf("conversations.replies not ok: %s", resp.Error))
			return nil
		}
		for _, msg := range resp.Messages {
			if err := visit(msg); err != nil {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					return err
				}
				continue
			}
		}
		cursor = resp.ResponseMetadata.NextCursor
		if !resp.HasMore || cursor == "" {
			break
		}
	}
	return nil
}

func emitSlackMessageIncremental(ctx context.Context, chInfo slackChannelInfo, msg slackMessage, state *slackScanState, emit Emit) error {
	key := slackMessageKey(chInfo.ID, msg.TS)
	current := slackMessageIncrementalState{Text: msg.Text}
	if state != nil && state.next != nil {
		state.mu.Lock()
		state.next.Messages[key] = current
		state.mu.Unlock()
	}
	if state != nil && state.previous != nil && state.previous.Messages[key] == current {
		return nil
	}
	return emitSlackMessage(ctx, chInfo, msg, emit)
}

func emitSlackFileIncremental(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, msg slackMessage, fileID, fileName, downloadURL string, state *slackScanState, emit Emit) error {
	key := slackFileKey(chInfo.ID, msg.TS, fileID)
	current := slackFileIncrementalState{Name: fileName, URLPrivateDownload: downloadURL}
	if state != nil && state.previous != nil && state.previous.Files[key] == current {
		state.recordFile(key, current)
		return nil
	}
	ok, err := emitSlackFile(ctx, cli, chInfo, msg, fileID, fileName, downloadURL, state, emit)
	if err != nil {
		return err
	}
	// A file that failed to fetch is left out of the next checkpoint so
	// the following incremental run retries it instead of skipping it.
	if ok {
		state.recordFile(key, current)
	}
	return nil
}

func (s *slackScanState) recordFile(key string, current slackFileIncrementalState) {
	if s == nil || s.next == nil {
		return
	}
	s.mu.Lock()
	s.next.Files[key] = current
	s.mu.Unlock()
}

func slackMessageKey(channel, ts string) string {
	return channel + ":" + ts
}

func slackFileKey(channel, ts, fileID string) string {
	return channel + ":" + ts + ":file:" + fileID
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

// emitSlackFile fetches and emits one attached file. ok reports whether the
// file was covered; provider failures are recorded on state and return
// ok=false with a nil error. Only cancellation and sink errors return.
func emitSlackFile(ctx context.Context, cli *slackClient, chInfo slackChannelInfo, msg slackMessage, fileID, fileName, downloadURL string, state *slackScanState, emit Emit) (bool, error) {
	src := "slack/" + chInfo.ID + "/file/" + fileID
	isCtx := func(err error) bool {
		return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	}
	if downloadURL == "" {
		var resp slackFilesInfoResp
		if err := cli.getJSON(ctx, "/api/files.info?file="+neturl.QueryEscape(fileID), &resp); err != nil {
			if isCtx(err) {
				return false, err
			}
			state.fail(src, fmt.Errorf("files.info: %w", err))
			return false, nil
		}
		if !resp.OK {
			state.fail(src, fmt.Errorf("files.info not ok: %s", resp.Error))
			return false, nil
		}
		downloadURL = resp.File.URLPrivateDownload
		fileName = resp.File.Name
	}
	if downloadURL == "" {
		// External/tombstoned files carry no downloadable body: nothing to cover.
		return true, nil
	}
	data, err := cli.download(ctx, downloadURL)
	if err != nil {
		if isCtx(err) {
			return false, err
		}
		state.fail(src, fmt.Errorf("download: %w", err))
		return false, nil
	}
	return true, emit(data, sources.Metadata{
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
	// Request paths already include `/api/`, so a base that also ends in
	// `/api` (the value historically documented for the api_base override)
	// would double it. Normalize to the host root.
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/api")
	return &slackClient{
		base:  base,
		token: token,
		http:  authenticatedHTTPClient(slackRequestTimeout),
	}
}

func (c *slackClient) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := c.waitForBucket(ctx); err != nil {
			return nil, err
		}
		target, err := c.url(path)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, target, body)
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
	if err := c.downloadAllowed(url); err != nil {
		return nil, err
	}
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

// downloadAllowed keeps the bearer token on Slack: url_private_download
// must be the API origin or an https *.slack.com file host (#865).
func (c *slackClient) downloadAllowed(target string) error {
	if sameOriginURL("slack", c.base, target) == nil {
		return nil
	}
	u, err := neturl.Parse(target)
	if err != nil {
		return errors.New("slack: malformed download URL")
	}
	host := strings.ToLower(u.Hostname())
	if u.Scheme == "https" && u.Port() == "" && (host == "slack.com" || strings.HasSuffix(host, ".slack.com")) {
		return nil
	}
	return fmt.Errorf("slack: refusing credentialed download from foreign origin %s://%s", u.Scheme, u.Host)
}

func (c *slackClient) url(p string) (string, error) {
	return apiURL("slack", c.base, p)
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
