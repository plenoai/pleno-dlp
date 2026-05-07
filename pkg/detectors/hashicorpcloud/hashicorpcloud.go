// Package hashicorpcloud detects HashiCorp Cloud Platform (HCP) access
// tokens (`hcp.…`) and verifies them against the IAM read endpoint.
package hashicorpcloud

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.cloud.hashicorp.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `hcp.` + 60+ url-safe base64 chars. HCP issues tokens with three internal
// dot-separated segments, but the leading `hcp.` is the unambiguous prefix.
var tokenRe = regexp.MustCompile(`\b(hcp\.[A-Za-z0-9_.-]{60,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.HashiCorpCloud }

func (Scanner) Keywords() []string { return []string{"hcp."} }

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
			DetectorType: detectors.HashiCorpCloud,
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

	// Read-only list call against the IAM organizations index. A valid
	// access token returns 200 with a JSON envelope; an invalid one returns
	// 401/403.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/iam/2019-12-10/iam/organizations", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
