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
//
// FORMAT RESEARCH (inconclusive on length/charset): The legacy Buffer REST
// API this detector verifies against (api.bufferapp.com/1/user.json) issues
// OAuth2 "long-lived access tokens", but no authoritative source pins their
// exact length or charset. The official legacy OAuth doc only shows the
// *authorization code* example `1/mWot20jTwojsd00jFlaaR45` and describes the
// access token merely as "long-lived"; SDK READMEs use a hand-typed
// placeholder (`1/jjjj…`). The newer GraphQL API returns JWT (`eyJ…`) access
// tokens — a different shape. trufflehog ships no buffer detector to mirror.
// Per the inconclusive-research fallback we do NOT re-pin the length/charset
// (the existing `{40,50}` window is the shipped contract) and instead apply
// recall-safe gate-tightening: a conservative entropy floor + a tighter
// proximity radius.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,50})\b`)

// minEntropy is the conservative recall-safe floor mandated for the
// inconclusive-format case. The candidate charset is alnum (no authoritative
// charset narrowing), but with no documented length/charset we use the
// hex-floor (3.0) rather than the alnum 3.5 so a real low-variety-but-genuine
// token is never culled. It rejects the degenerate runs (`aaaa…`, repeated
// `abcdabcd…`, padded identifiers) that clear `{40,50}` near a buffer marker.
const minEntropy = 3.0

// keywordRe is the anchored Buffer.com marker. The bare substring
// `buffer` is ubiquitous in source code; paired with a 40-char alnum
// token shape it matches every git SHA-1 in a repo. The regex demands a
// Buffer-app anchor so unrelated buffers in code don't pull the trigger.
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
		// Entropy gate: a 40-50 char alnum run near a buffer marker is not
		// enough on its own (commit SHAs, padded identifiers, repeated
		// patterns clear the regex). Conservative 3.0 floor — see minEntropy.
		if !detectors.HasMinEntropy(token, minEntropy) {
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
	const radius = 64
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
