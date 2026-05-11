// Package totango detects Totango customer-success service tokens near
// the `totango` keyword. Unverified by design — Totango uses per-tenant
// hosts (`<tenant>.totango.com`) plus a custom `app-token` header, so
// verify only fires when an apiBase override is supplied. Canonical
// probe is /api/v3/accounts/search.
//
// "totango" is not an English word, so the keyword name itself is
// safe; the FP source was the token regex `[A-Za-z0-9]{32,64}`, which
// matches every 32+ char alphanumeric blob in the same chunk. We now
// require an explicit Totango anchor (`totango_api`, `totango_token`,
// `totango.com`, `TOTANGO=`) and keep the regex shape.
package totango

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Totango service tokens are 32-64 alnum chars; anchored on an
// explicit Totango keyword.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// keywordRe requires an explicit Totango anchor. The bare substring
// "totango" appearing inside an unrelated identifier no longer
// qualifies on its own — though since the word isn't a real English
// word, the most important effect is requiring a token-like
// neighbouring context.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`totango[_\-]api(?:[_\-]key|[_\-]token)?` +
	`|totango[_\-]token` +
	`|totango[_\-]key` +
	`|totango[_\-]app[_\-]token` +
	`|\btotango\.com\b` +
	`|\btotango[ \t]*[:=][ \t]*` +
	`|\bapp[_\-]token\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Totango }

func (Scanner) Keywords() []string { return []string{"totango"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	// `app-token` alone is too generic; require a totango-anchored
	// keyword somewhere in the chunk as well.
	if !hasTotangoAnchor(data) {
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
		// Totango tokens are 32-64 char alnum; reject all-zero /
		// repeated-pattern noise.
		if !detectors.HasMinEntropy(token, 3.5) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Totango,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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

// totangoAnchorRe matches "totango" with a non-letter boundary
// (start-of-string, whitespace, `_`, `-`, `.`, `=`, `:`, end-of-word).
// `\btotango\b` is wrong because `\b` treats `_` as a word char, so
// `TOTANGO_TOKEN` would fail the boundary check.
var totangoAnchorRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z])totango(?:[^A-Za-z]|$)`)

func hasTotangoAnchor(data []byte) bool {
	return totangoAnchorRe.Match(data)
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 128
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
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v3/accounts/search", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("app-token", secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
}

func redact(t string) string {
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
