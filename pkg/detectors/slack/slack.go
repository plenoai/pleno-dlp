// Package slack detects Slack bot tokens (xoxb-…) and verifies them against
// auth.test.
package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://slack.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// xoxb-<workspace_id>-<bot_id>-<secret>. The trailing run is base62-ish; we
// require at least 24 chars to avoid latching on truncated samples.
var tokenRe = regexp.MustCompile(`\b(xoxb-\d+-\d+-[A-Za-z0-9]{24,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SlackBotToken }

func (Scanner) Keywords() []string { return []string{"xoxb-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		res := detectors.Result{
			DetectorType: detectors.SlackBotToken,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/auth.test", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, nil
	}
	return body.OK, nil
}

func redact(t string) string {
	if len(t) <= 5 {
		return t
	}
	return t[:5] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
