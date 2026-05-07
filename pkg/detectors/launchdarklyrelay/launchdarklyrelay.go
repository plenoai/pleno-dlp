// Package launchdarklyrelay detects LaunchDarkly relay-proxy service tokens.
//
// Relay-proxy tokens are issued separately from the project access (`api-`)
// and SDK (`sdk-`) keys handled by `pkg/detectors/launchdarkly`. They start
// with `relay-proxy-` and authorise the relay daemon to fetch flag payloads
// for one or more environments. We verify against the same host as the
// regular launchdarkly detector but with a relay-specific endpoint
// (/relay/health) that only relay-proxy tokens can read.
package launchdarklyrelay

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.launchdarkly.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `relay-proxy-` + UUID. Same UUID body as access keys but the prefix is
// distinctive.
var tokenRe = regexp.MustCompile(`\b(relay-proxy-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LaunchDarklyRelay }

func (Scanner) Keywords() []string { return []string{"relay-proxy-"} }

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
			DetectorType: detectors.LaunchDarklyRelay,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/relay/health", nil)
	if err != nil {
		return false, err
	}
	// LaunchDarkly's REST API uses the raw token in Authorization (no scheme).
	req.Header.Set("Authorization", secret)

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
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
