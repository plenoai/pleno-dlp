// Package mailchimp detects Mailchimp API keys (32 hex + "-us" + dc number)
// and verifies them against the per-datacenter API root.
//
// Mailchimp's API host is keyed by the data-center slug embedded in the
// token's suffix (e.g. "...-us17" → us17.api.mailchimp.com). We extract the
// dc, build the URL, and probe / with Basic auth ("anystring" as username,
// per Mailchimp docs).
package mailchimp

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiURLForDC returns the per-DC URL. Test-overridable via apiBaseOverride
// so httptest servers can hijack the request without shelling out per-DC.
var apiBaseOverride = ""

func apiURLForDC(dc string) string {
	if apiBaseOverride != "" {
		return apiBaseOverride
	}
	return "https://" + dc + ".api.mailchimp.com/3.0/"
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32 hex + literal "-us" + 1-2 digit DC number. Mailchimp DCs are
// us1..us2x range; we accept 1-2 digits to stay forward-compatible.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{32}-us[0-9]{1,2})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mailchimp }

func (Scanner) Keywords() []string { return []string{"-us"} }

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
			DetectorType: detectors.Mailchimp,
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

// extractDC returns the "us<n>" portion of a Mailchimp token, e.g. "us17".
func extractDC(token string) (string, bool) {
	i := strings.LastIndex(token, "-")
	if i < 0 || i+1 >= len(token) {
		return "", false
	}
	return token[i+1:], true
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	dc, ok := extractDC(secret)
	if !ok {
		return false, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURLForDC(dc), nil)
	if err != nil {
		return false, err
	}
	// Mailchimp accepts any string as the Basic-auth username — "anystring"
	// is the documented placeholder.
	req.SetBasicAuth("anystring", secret)

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
	// Keep first 8 hex, then suffix "-us<dc>" stays in the redacted form so
	// reviewers still see the data center routing without the credential.
	if len(t) <= 8 {
		return t
	}
	if i := strings.LastIndex(t, "-us"); i > 8 {
		return t[:8] + "..." + t[i:]
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
