package slack

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var webhookRe = regexp.MustCompile(`\bhttps://hooks\.slack(?:-gov)?\.com/services/[A-Z0-9]{8,13}/[A-Z0-9]{8,13}/[A-Za-z0-9]{24}\b`)

var slackWebhookVerifyBase string

type WebhookScanner struct{}

func (WebhookScanner) Type() detectors.DetectorType { return detectors.SlackWebhook }

func (WebhookScanner) Keywords() []string {
	return []string{"hooks.slack.com", "hooks.slack-gov.com"}
}

func (s WebhookScanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := webhookRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		webhookURL := string(m)
		if _, dup := seen[webhookURL]; dup {
			continue
		}
		seen[webhookURL] = struct{}{}

		res := detectors.Result{
			DetectorType: detectors.SlackWebhook,
			Raw:          []byte(webhookURL),
			Redacted:     redactWebhook(webhookURL),
		}
		if verify {
			v, err := s.Verify(ctx, webhookURL)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (WebhookScanner) Verify(ctx context.Context, secret string) (bool, error) {
	verifyURL, ok := slackWebhookVerifyURL(secret)
	if !ok {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, verifyURL, bytes.NewReader(nil))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := strings.TrimSpace(string(body))

	switch resp.StatusCode {
	case http.StatusBadRequest:
		return msg == "invalid_payload" || msg == "no_text", nil
	case http.StatusNotFound, http.StatusGone, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return false, fmt.Errorf("slack webhook verify: server error: %s", resp.Status)
	}
	return false, nil
}

func slackWebhookVerifyURL(secret string) (string, bool) {
	if webhookRe.FindString(secret) != secret {
		return "", false
	}
	u, err := url.Parse(secret)
	if err != nil || u.Scheme != "https" || !isSlackWebhookHost(u.Host) || !strings.HasPrefix(u.Path, "/services/") {
		return "", false
	}
	if slackWebhookVerifyBase == "" {
		return secret, true
	}
	base, err := url.Parse(slackWebhookVerifyBase)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return "", false
	}
	u.Scheme = base.Scheme
	u.Host = base.Host
	return u.String(), true
}

func isSlackWebhookHost(host string) bool {
	return host == "hooks.slack.com" || host == "hooks.slack-gov.com"
}

func redactWebhook(webhookURL string) string {
	parts := strings.Split(webhookURL, "/")
	if len(parts) >= 7 {
		return strings.Join(parts[:6], "/") + "/..."
	}
	if len(webhookURL) <= 32 {
		return webhookURL
	}
	return webhookURL[:32] + "..."
}

var (
	_ detectors.Detector = WebhookScanner{}
	_ detectors.Verifier = WebhookScanner{}
)

func init() {
	detectors.Register(WebhookScanner{})
}
