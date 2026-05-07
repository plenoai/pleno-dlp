// Package pulumi detects Pulumi Cloud access tokens (`pul-` prefix +
// 40-hex) and verifies them against /api/user using the documented
// `Authorization: token <pat>` header.
//
// Pulumi access tokens grant the issuing user's full org-stack scope
// (read+write infrastructure state). The `pul-` prefix is distinctive
// enough that no keyword gate is required, but we still keep `pulumi`
// in the prefilter list for the engine.
package pulumi

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.pulumi.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(pul-[a-f0-9]{40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pulumi }

func (Scanner) Keywords() []string { return []string{"pul-", "pulumi"} }

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
			DetectorType: detectors.Pulumi,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/user", nil)
	if err != nil {
		return false, err
	}
	// Pulumi uses `token <pat>` (lowercase, single space) per the
	// documented Pulumi Service API form.
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.pulumi+8")

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
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
