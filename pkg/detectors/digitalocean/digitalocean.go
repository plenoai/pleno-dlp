// Package digitalocean detects DigitalOcean personal access tokens
// (dop_v1_<64 hex>) and verifies them via /v2/account.
package digitalocean

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.digitalocean.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// dop_v1_ prefix + 64 hex chars. The provider-specific prefix means the regex
// is precise enough that we don't need a co-occurring keyword.
var tokenRe = regexp.MustCompile(`\b(dop_v1_[a-f0-9]{64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DigitalOcean }

func (Scanner) Keywords() []string { return []string{"dop_v1_"} }

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
			DetectorType: detectors.DigitalOcean,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
	// Keep "dop_v1_" prefix + first 4 of the hex tail.
	if len(t) <= 11 {
		return t
	}
	return t[:11] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
