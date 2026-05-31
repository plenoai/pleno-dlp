// Package bamboo detects Atlassian Bamboo personal access tokens (>=24
// base64 chars) gated on the `bamboo` keyword window. Bamboo is self-hosted,
// so the server URL is genuinely absent from the chunk; verification is
// performed only when an apiBase host is supplied (apiBase-override pattern,
// same as front/drata/heap). Without apiBase the verify path no-ops and the
// finding is surfaced unverified — live verify, not regex shape, is what
// distinguishes a real PAT from an arbitrary base64 blob.
package bamboo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is empty by default: Bamboo is self-hosted and the host is not in
// the chunk. Operators supply it via configuration; tests override it. When
// empty, Verify no-ops (returns false, nil) so a non-PAT base64 blob is never
// falsely reported as Verified.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9+/=]{24,64})\b`)

var contextKeywords = []string{"bamboo", "bamboo_token", "bamboo_pat", "bamboo_api"}

// Bamboo's REST API accepts a PAT directly as Authorization: Bearer <token>.
var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound}
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bamboo }

func (Scanner) Keywords() []string { return []string{"bamboo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Bamboo,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// Verify checks the token against a Bamboo server's REST API. Bamboo is
// self-hosted, so the host must be supplied via apiBase; when apiBase is empty
// the verify is a no-op (false, nil) — we cannot reach a host we do not know,
// and we must never guess. With a host, the token is presented as
// Authorization: Bearer <token> against /rest/api/latest/currentUser.json.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := strings.TrimRight(apiBase, "/") + "/rest/api/latest/currentUser.json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, err, verifyAcceptCodes, verifyRejectCodes)
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
