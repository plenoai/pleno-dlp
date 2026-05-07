// Package launchdarkly detects LaunchDarkly access (`api-<uuid>`) and SDK
// (`sdk-<uuid>`) keys, verifying access keys against /api/v2/projects.
package launchdarkly

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.launchdarkly.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `api-` or `sdk-` + UUID. The hyphenated UUID anchored to the prefix is
// distinctive enough to skip a keyword gate.
var tokenRe = regexp.MustCompile(`\b((?:api|sdk)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LaunchDarkly }

func (Scanner) Keywords() []string { return []string{"api-", "sdk-", "launchdarkly"} }

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
			DetectorType: detectors.LaunchDarkly,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Only `api-` keys can read /api/v2/projects. `sdk-` keys are
		// front-end / mobile keys and don't authenticate against the REST
		// API; surface them unverified.
		if verify && strings.HasPrefix(token, "api-") {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/projects", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
