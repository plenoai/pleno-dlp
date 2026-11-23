// Package alerts posts an end-of-scan summary of findings to one or more
// webhooks (Slack, Microsoft Teams, or a generic JSON endpoint).
//
// Alerting is best-effort: delivery failures are reported to the caller as
// warnings and must never change the scan's exit code. Payloads never carry
// raw secret material — only the detector's display-safe redaction, the
// location, severity, and verdict.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/output"
)

// Format is a webhook payload shape.
type Format string

const (
	FormatSlack   Format = "slack"
	FormatTeams   Format = "teams"
	FormatGeneric Format = "generic"
)

// maxListed caps per-finding lines rendered in chat payloads; the totals
// still count every finding.
const maxListed = 25

// InferFormat picks the payload shape from the webhook host.
func InferFormat(u *url.URL) Format {
	h := strings.ToLower(u.Hostname())
	switch {
	case h == "slack.com" || strings.HasSuffix(h, ".slack.com"):
		return FormatSlack
	case h == "office.com" || strings.HasSuffix(h, ".office.com"),
		strings.HasPrefix(h, "webhook.office."),
		strings.HasSuffix(h, ".logic.azure.com"):
		return FormatTeams
	default:
		return FormatGeneric
	}
}

// Webhook is a validated destination.
type Webhook struct {
	URL    *url.URL
	Format Format
}

// ParseWebhook validates raw (https only, except loopback http for tests and
// local relays) and infers its format.
func ParseWebhook(raw string) (Webhook, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return Webhook{}, fmt.Errorf("invalid --alert-webhook %s", RedactURL(raw))
	}
	switch u.Scheme {
	case "https":
	case "http":
		h := u.Hostname()
		if h != "localhost" && h != "127.0.0.1" && h != "::1" {
			return Webhook{}, fmt.Errorf("--alert-webhook %s: https required (http allowed only for loopback)", RedactURL(raw))
		}
	default:
		return Webhook{}, fmt.Errorf("--alert-webhook %s: https required", RedactURL(raw))
	}
	return Webhook{URL: u, Format: InferFormat(u)}, nil
}

// RedactURL keeps only scheme and host: webhook paths and queries embed the
// bearer token for Slack/Teams incoming webhooks.
func RedactURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "<redacted-url>"
	}
	return u.Scheme + "://" + u.Host + "/<redacted>"
}

// Finding is the secret-free projection sent to webhooks.
type Finding struct {
	Detector string `json:"detector"`
	Severity string `json:"severity"`
	Verdict  string `json:"verdict"`
	Redacted string `json:"redacted"`
	Location string `json:"location"`

	sev detectors.Severity
}

// Summary is the generic JSON payload.
type Summary struct {
	Tool        string         `json:"tool"`
	Version     string         `json:"version,omitempty"`
	Source      string         `json:"source"`
	MinSeverity string         `json:"min_severity"`
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"by_severity"`
	Findings    []Finding      `json:"findings"`
}

// Collector is an engine.Sink tee that records the redacted projection of
// every finding at or above MinSeverity and forwards to Inner unchanged.
type Collector struct {
	Inner       engine.Sink
	MinSeverity detectors.Severity

	mu       sync.Mutex
	findings []Finding
}

func (c *Collector) Emit(f engine.Finding) {
	if f.Result.Severity >= c.MinSeverity {
		af := Finding{
			Detector: f.Detector.String(),
			Severity: f.Result.Severity.String(),
			Verdict:  f.Result.Verdict().String(),
			Redacted: f.Result.SafeRedacted(),
			Location: output.LocationOf(f),
			sev:      f.Result.Severity,
		}
		c.mu.Lock()
		c.findings = append(c.findings, af)
		c.mu.Unlock()
	}
	c.Inner.Emit(f)
}

func (c *Collector) Close() error { return c.Inner.Close() }

// Findings returns a copy of the recorded findings.
func (c *Collector) Findings() []Finding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]Finding(nil), c.findings...)
}

// Notifier delivers a Summary to its webhooks.
type Notifier struct {
	Webhooks []Webhook
	Client   *http.Client
	// Retries is the number of additional attempts after the first on
	// network errors, 429, and 5xx.
	Retries int
	Backoff time.Duration
	DryRun  bool
	// Log receives dry-run payloads and warnings (stderr in the CLI).
	Log io.Writer
}

// BuildSummary assembles the generic payload.
func BuildSummary(version, source string, min detectors.Severity, fs []Finding) Summary {
	s := Summary{Tool: "pleno-dlp", Version: version, Source: source, MinSeverity: min.String(),
		Total: len(fs), BySeverity: map[string]int{}, Findings: fs}
	if s.Findings == nil {
		s.Findings = []Finding{}
	}
	for _, f := range fs {
		s.BySeverity[f.Severity]++
	}
	return s
}

func (s Summary) headline() string {
	parts := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		if n := s.BySeverity[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	return fmt.Sprintf("pleno-dlp: %d finding(s) in %s (%s)", s.Total, s.Source, strings.Join(parts, ", "))
}

func (s Summary) lines() []string {
	var out []string
	for i, f := range s.Findings {
		if i == maxListed {
			out = append(out, fmt.Sprintf("… and %d more", len(s.Findings)-maxListed))
			break
		}
		out = append(out, fmt.Sprintf("[%s] %s %s at %s (%s)", f.Severity, f.Detector, f.Redacted, f.Location, f.Verdict))
	}
	return out
}

// Payload renders s in format.
func Payload(format Format, s Summary) ([]byte, error) {
	switch format {
	case FormatSlack:
		text := s.headline()
		if l := s.lines(); len(l) > 0 {
			text += "\n• " + strings.Join(l, "\n• ")
		}
		return json.Marshal(map[string]string{"text": text})
	case FormatTeams:
		body := []map[string]any{{"type": "TextBlock", "text": s.headline(), "weight": "Bolder", "wrap": true}}
		for _, l := range s.lines() {
			body = append(body, map[string]any{"type": "TextBlock", "text": l, "wrap": true})
		}
		return json.Marshal(map[string]any{
			"type": "message",
			"attachments": []map[string]any{{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard", "version": "1.4", "body": body,
				},
			}},
		})
	default:
		return json.Marshal(s)
	}
}

// Send posts s to every webhook. It returns one error per failed webhook,
// with URLs redacted. With DryRun it writes each payload to Log instead.
func (n *Notifier) Send(ctx context.Context, s Summary) error {
	var errs []error
	for _, w := range n.Webhooks {
		body, err := Payload(w.Format, s)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		red := RedactURL(w.URL.String())
		if n.DryRun {
			if n.Log != nil {
				fmt.Fprintf(n.Log, "alert dry-run: %s (%s): %s\n", red, w.Format, body)
			}
			continue
		}
		if err := n.post(ctx, w.URL.String(), body); err != nil {
			errs = append(errs, fmt.Errorf("alert %s: %w", red, err))
		}
	}
	return errors.Join(errs...)
}

func (n *Notifier) post(ctx context.Context, u string, body []byte) error {
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	// Never follow redirects: the webhook URL is the credential and a
	// redirect could forward the payload elsewhere.
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	backoff := n.Backoff
	if backoff <= 0 {
		backoff = 500 * time.Millisecond
	}
	var last error
	for attempt := 0; attempt <= n.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return errors.Join(last, ctx.Err())
			case <-time.After(backoff << (attempt - 1)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
		if err != nil {
			return errors.New("build request failed")
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "pleno-dlp-alerts")
		resp, err := c.Do(req)
		if err != nil {
			// *url.Error embeds the full URL (and its token); drop it.
			var ue *url.Error
			if errors.As(err, &ue) {
				err = ue.Err
			}
			last = fmt.Errorf("attempt %d: %v", attempt+1, err)
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			last = fmt.Errorf("attempt %d: HTTP %d", attempt+1, resp.StatusCode)
		default:
			return fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	return last
}
