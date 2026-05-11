// Package pumble detects Pumble (pumble.com) team-chat API tokens — long
// alphanumeric tokens near the `pumble` keyword. Verified via the
// addons marketplace /listUsers endpoint using an `Api-Key` header.
//
// "pumble" is not an English word, so the keyword gate is less
// fragile than e.g. expo/drift/lever. The real FP source was the
// token regex itself: `[A-Za-z0-9]{40,80}` matches JWT mid-segments,
// base64-encoded payloads, npm sha512 fragments, and other opaque
// 40+ char blobs that frequently appear next to the word "pumble" in
// docs, comments, or unrelated keys. The new detector requires:
//
//   1. an explicit anchor (`pumble_api`, `pumble_token`, `pumble.com`,
//      `PUMBLE=`) — bare "pumble" in prose no longer satisfies; and
//   2. a token that is base64url-ish with at least one underscore /
//      dash OR a long pure-alphanumeric string, but only when one of
//      the explicit anchors lies within 96 bytes.
package pumble

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://pumble-api-keys.addons.marketplace.cake.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Pumble personal API tokens are 40-80 char base64url strings.
// Trufflehog upstream regex matches `[A-Za-z0-9]{40,80}`; we keep
// that shape but rely on the much tighter keyword gate below.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// keywordRe requires an explicit Pumble anchor. The bare "pumble"
// substring is still cheap to find, but it must be followed by a
// non-letter or a known suffix to register.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`pumble[_\-]api(?:[_\-]key|[_\-]token)?` +
	`|pumble[_\-]token` +
	`|pumble[_\-]key` +
	`|\bpumble\.com\b` +
	`|\bpumble[ \t]*[:=][ \t]*` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pumble }

func (Scanner) Keywords() []string { return []string{"pumble"} }

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
			DetectorType: detectors.Pumble,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/listUsers", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Api-Key", secret)
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
