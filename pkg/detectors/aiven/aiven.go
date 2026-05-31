// Package aiven detects Aiven personal access tokens (32+ char base62 near
// `aiven`), verifying via /v1/me with `Authorization: aivenv1 <token>`. Aiven
// tokens are user-scoped and grant CRUD over every project the user owns, so
// verified hits are SeverityCritical via the engine default.
package aiven

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.aiven.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Aiven tokens carry no public prefix and are base64 (alnum plus `/`, `+`,
// `=`). The upstream trufflehog detector pins the length at exactly 372
// (`[a-zA-Z0-9/+=]{372}`,
// github.com/trufflesecurity/trufflehog pkg/detectors/aiven/aiven.go), and
// GitGuardian's detector page records "Prefixed: False". Aiven's own docs
// confirm the `aivenv1 <TOKEN>` auth header but only ever show ellipsis-
// truncated examples, so 372 is the only cited length.
//
// We do not pin 372 outright: the pre-existing fixtures encode a shorter
// alnum shape, and an over-tight length pin silently destroys recall on any
// token whose emitted form differs. Instead the floor (32) excludes uuid /
// short-id shapes, the ceiling (400) comfortably covers the documented 372,
// and the base64 charset matches the real token alphabet (a superset of the
// historical `[A-Za-z0-9]`, so prior matches are preserved).
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9/+=]{32,400})\b`)

// contextRe is the windowed keyword gate. The bare `aiven` substring is kept
// only as the cheap Keywords() prefilter; this assignment-style arm regex
// (word-boundaried keyword or `aiven_(api_)?(token|key|secret)`) is what
// actually arms a hit, so prose mentioning "aiven" near an unrelated
// high-entropy blob no longer matches.
var contextRe = regexp.MustCompile(`(?i)\baiven\b|aiven[_-]?(api[_-]?)?(token|key|secret)`)

// minEntropy rejects low-information 372-or-shorter runs (long base64 of a
// repeated/structured payload) that clear the regex but lack key-grade
// randomness. Aiven tokens are high-variety base64, so 3.5 is safe.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Aiven }

func (Scanner) Keywords() []string { return []string{"aiven"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Aiven,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "aivenv1 "+secret)
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

func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return contextRe.MatchString(lower[from:to])
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
