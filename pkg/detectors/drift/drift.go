// Package drift detects Drift (drift.com) API tokens — long base64url tokens
// near `drift` keyword. Verified via /core/v1/users/list on driftapi.com using
// `Authorization: Bearer <token>`.
//
// The "drift" substring lives inside several common English words —
// `drifted`, `drifting`, `adrift`, `redrift`. The previous detector
// did `strings.Contains(window, "drift")` and therefore fired on any
// 32+ char alphanumeric blob in prose / changelogs / commit logs that
// happened to mention the word. The new detector requires an explicit
// separator (`drift_api`, `drift_token`, `drift.com`, `DRIFT=`).
package drift

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://driftapi.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Drift API tokens are documented JWT-shaped strings (three
// base64url segments separated by dots). Trufflehog upstream uses
// `eyJ[A-Za-z0-9_-]{50,300}\.[A-Za-z0-9_-]{30,300}\.[A-Za-z0-9_-]{30,300}`.
// We narrow to this JWT shape because the prior `[A-Za-z0-9_-]{32,80}`
// collided with virtually every base64-encoded blob (commit-shaped
// hashes, npm sha512 fragments, base32 UUIDs, JWT-mid-segments).
var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{20,200}\.[A-Za-z0-9_\-]{10,300}\.[A-Za-z0-9_\-]{10,300})\b`)

// keywordRe requires an explicit separator so words like `drifted`,
// `drifting`, `adrift` no longer qualify. Case-insensitive.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`drift[_\-]api(?:[_\-]token)?` +
	`|drift[_\-]token` +
	`|drift[_\-]access[_\-]token` +
	`|\bdrift\.com\b` +
	`|\bdriftapi\.com\b` +
	`|\bdrift[ \t]*[:=][ \t]*` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Drift }

func (Scanner) Keywords() []string { return []string{"drift"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Drift,
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

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 256
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/core/v1/users/list", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
