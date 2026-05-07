// Package notion detects Notion integration tokens (secret_<43>) and
// verifies them against /v1/users/me. The Notion-Version header is
// mandatory — Notion rejects unversioned requests with 400, which would
// invert our verify signal.
package notion

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.notion.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(secret_[A-Za-z0-9]{43})\b`)

// Pinned to the latest stable Notion API version. Updating this is a
// coordinated change because old tokens may behave differently across
// versions; track it via ADR if upstream forces an upgrade.
const notionVersion = "2022-06-28"

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Notion }

func (Scanner) Keywords() []string { return []string{"secret_"} }

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
			DetectorType: detectors.Notion,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Notion-Version", notionVersion)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	// Keep "secret_" + 4 chars after = 11 chars.
	if len(t) <= 11 {
		return t
	}
	return t[:11] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
