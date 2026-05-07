// Package buildkite detects Buildkite agent tokens (`bkua_<40 hex>`) and API
// access tokens (`bka_<40 alnum>` or 40-char hex with the "buildkite" keyword),
// verifying API tokens against /v2/user.
package buildkite

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.buildkite.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// `bkua_` + 40 hex (agent registration token).
	agentRe = regexp.MustCompile(`\b(bkua_[a-f0-9]{40})\b`)
	// `bka_` + 40 alnum (Buildkite documents this as the API access token
	// shape on newly-minted tokens).
	apiRe = regexp.MustCompile(`\b(bka_[A-Za-z0-9]{40})\b`)
	// Legacy 40-char hex API tokens (no prefix). Keyword-gated.
	legacyRe = regexp.MustCompile(`\b([a-f0-9]{40})\b`)
)

var contextKeywords = []string{"buildkite", "buildkite_api_token", "buildkite_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Buildkite }

func (Scanner) Keywords() []string { return []string{"bkua_", "bka_", "buildkite"} }

// span is a half-open [a,b) byte range used to suppress legacy hex matches
// that overlap a prefix-anchored hit.
type span struct{ a, b int }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}
	// Track index ranges already claimed by a prefix-anchored match so the
	// legacy hex pass doesn't double-count the hex portion of `bkua_<hex>`.
	claimed := []span{}

	for _, h := range agentRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		claimed = append(claimed, span{h[2], h[3]})
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		// Agent tokens authenticate against agent.buildkite.com, not the
		// REST API — we don't try to verify them but still surface.
		out = append(out, detectors.Result{
			DetectorType: detectors.Buildkite,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}

	for _, h := range apiRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		claimed = append(claimed, span{h[2], h[3]})
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Buildkite,
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

	legacyHits := legacyRe.FindAllSubmatchIndex(data, -1)
	if len(legacyHits) > 0 {
		lower := strings.ToLower(string(data))
		for _, h := range legacyHits {
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
				DetectorType: detectors.Buildkite,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/user", nil)
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
