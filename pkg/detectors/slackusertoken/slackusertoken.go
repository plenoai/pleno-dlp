// Package slackusertoken detects Slack user OAuth tokens (xoxp-) — distinct
// from xoxb- bot tokens already handled by pkg/detectors/slack. xoxp- grants
// user-level scope, which is broader than bot tokens and warrants its own
// detector. Verified via auth.test on slack.com.
package slackusertoken

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

// xoxp-<workspace>-<user>-<num>-<secret>. Trailing run is base62-ish; require
// at least 24 chars to avoid latching on truncated samples.
var tokenRe = regexp.MustCompile(`\b(xoxp-\d+-\d+-\d+-[A-Za-z0-9]{24,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SlackUserToken }

func (Scanner) Keywords() []string { return []string{"xoxp-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.SlackUserToken,
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
