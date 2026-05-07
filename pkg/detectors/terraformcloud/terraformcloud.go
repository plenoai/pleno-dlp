// Package terraformcloud detects Terraform Cloud / Enterprise API tokens
// (<14 alnum>.atlasv1.<60+ url-safe>) and verifies them against
// /api/v2/account/details.
package terraformcloud

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.terraform.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 14 alnum + ".atlasv1." + url-safe tail of 60+ chars. The "atlasv1" infix
// is the legacy Atlas (HashiCorp's old name) marker that's still embedded in
// Terraform Cloud user tokens.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TerraformCloud }

func (Scanner) Keywords() []string { return []string{".atlasv1."} }

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
			DetectorType: detectors.TerraformCloud,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/account/details", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.api+json")

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
	// Keep the 14-char id prefix + ".atlasv1." marker.
	if len(t) <= 23 {
		return t
	}
	return t[:23] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
