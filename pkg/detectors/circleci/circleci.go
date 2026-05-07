// Package circleci detects CircleCI personal API tokens (`CCIPRJ_<43>` for
// project tokens, or 40-char hex personal API tokens with the "circleci"
// keyword), verifying via /api/v2/me with the Circle-Token header.
package circleci

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://circleci.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// `CCIPRJ_` + 43 base64url-ish chars (project-scoped token).
	projectRe = regexp.MustCompile(`\b(CCIPRJ_[A-Za-z0-9_-]{43})\b`)
	// 40-char lowercase hex (legacy personal API token shape).
	hexRe = regexp.MustCompile(`\b([a-f0-9]{40})\b`)
)

var contextKeywords = []string{"circleci", "circle_token", "circleci_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CircleCI }

func (Scanner) Keywords() []string { return []string{"CCIPRJ_", "circleci"} }

// span is a half-open [a,b) byte range used to suppress hex matches that
// overlap a prefix-anchored project-token hit.
type span struct{ a, b int }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}
	claimed := []span{}

	for _, h := range projectRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		claimed = append(claimed, span{h[2], h[3]})
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.CircleCI,
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

	hexHits := hexRe.FindAllSubmatchIndex(data, -1)
	if len(hexHits) > 0 {
		lower := strings.ToLower(string(data))
		for _, h := range hexHits {
			if overlapsAny(h[2], h[3], claimed) {
				continue
			}
			token := string(data[h[2]:h[3]])
			if _, dup := seen[token]; dup {
				continue
			}
			if !nearKeyword(lower, h[2], h[3]) {
				continue
			}
			seen[token] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.CircleCI,
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
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func overlapsAny(a, b int, spans []span) bool {
	for _, s := range spans {
		if a < s.b && b > s.a {
			return true
		}
	}
	return false
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/me", nil)
	if err != nil {
		return false, err
	}
	// CircleCI uses a custom header rather than Authorization: Bearer.
	req.Header.Set("Circle-Token", secret)

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
