// Package cockroachcloud detects Cockroach Labs CockroachDB Cloud API keys
// (`ccdb_<base62>`). The `ccdb_` prefix is distinctive enough to skip the
// keyword gate, but we still gate on `cockroach` to avoid colliding with
// shapes that legitimately start with `ccdb_` outside Cockroach context.
// Verification uses /api/v1/clusters with Bearer auth.
package cockroachcloud

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://cockroachlabs.cloud"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `ccdb_` literal + 32-80 base62 (Cockroach mints variable-length tokens
// depending on scope).
var tokenRe = regexp.MustCompile(`\b(ccdb_[A-Za-z0-9]{32,80})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CockroachCloud }

func (Scanner) Keywords() []string { return []string{"ccdb_"} }

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
			DetectorType: detectors.CockroachCloud,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/clusters", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")

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
