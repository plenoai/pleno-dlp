// Package buffer detects Buffer (social-media scheduling) API access tokens
// near the `buffer` keyword. Verified via /1/user.json on api.bufferapp.com
// with the access_token query parameter.
package buffer

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.bufferapp.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Buffer access tokens are 40-50 alnum chars (sometimes containing `/` and
// `+` from base64); we accept the URL-safe alnum subset which matches the
// observed token shape.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,50})\b`)

// keywordRe is the anchored Buffer.com marker. The bare substring
// `buffer` is ubiquitous in source code (byte buffer, ring buffer,
// strings.Builder docs); paired with a 40-char alnum token shape it
// matches every git SHA-1 in a repo. The regex demands a Buffer-app
// anchor so unrelated buffers in code don't pull the trigger.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bbufferapp\b` +
	`|\bbuffer\.com\b` +
	`|\bapi\.bufferapp\.com\b` +
	`|\bbuffer[_\-](?:api|token|access[_\-]?token|app)\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Buffer }

func (Scanner) Keywords() []string { return []string{"buffer"} }

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
			DetectorType: detectors.Buffer,
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
	q := url.Values{"access_token": {secret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/1/user.json?"+q.Encode(), nil)
	if err != nil {
		return false, err
	}
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
