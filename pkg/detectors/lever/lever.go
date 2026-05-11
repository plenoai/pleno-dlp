// Package lever detects Lever recruiting API keys — 40-character hex strings
// near the `lever` keyword. Verified via /v1/users on api.lever.co with HTTP
// Basic auth (key as username, blank password).
//
// "lever" is a substring of common English words (leveraged, however,
// leveling, cleverest, lever-arm, reliever) and the documented token
// shape `[a-f0-9]{40}` is identical to a git SHA-1, which appears
// thousands of times in any non-trivial repository. The previous
// detector did `strings.Contains(window, "lever")` over a 256-byte
// window, so any commit log near the word "leverage" produced FPs on
// every commit hash. The new detector requires explicit anchors:
// `lever_api`, `lever_token`, `api.lever.co`, `LEVER=`, etc.
package lever

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lever.co"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Lever API keys are documented as 40-char lower-hex strings. This
// shape is identical to a git SHA-1, so the surrounding keyword
// regex is the real gate.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{40})\b`)

// keywordRe requires an explicit Lever anchor — `lever_api`,
// `lever_token`, `lever.co`, `api.lever.co`, or `LEVER` followed by
// an assignment operator. The bare substring "lever" no longer
// qualifies, so "leveraged" / "however" / "cleverest" prose is
// rejected.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`lever[_\-]api(?:[_\-]key|[_\-]token)?` +
	`|lever[_\-]token` +
	`|lever[_\-]key` +
	`|\bapi\.lever\.co\b` +
	`|\blever\.co\b` +
	`|\blever[ \t]*[:=][ \t]*` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lever }

func (Scanner) Keywords() []string { return []string{"lever"} }

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
			DetectorType: detectors.Lever,
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
	const radius = 96
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
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
