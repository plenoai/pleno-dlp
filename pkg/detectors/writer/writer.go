// Package writer detects Writer.com (writer.com) generative-AI Writer-Key
// API tokens — long alphanumerics near the `writer` keyword. Verified via
// /v1/models on api.writer.com with Bearer auth (Authorization: Bearer
// <TOKEN>).
//
// Writer.com does not publish an authoritative API-key format: dev.writer.com
// (api-reference/api-keys, quickstart) and the official writer-python /
// writer-node SDKs show only `<your-api-key>` placeholders, and trufflehog
// has no upstream Writer detector to mirror. The token shape therefore stays
// a generic 40-128 alnum run; FP defense leans on the conservative entropy
// floor plus the assignment-anchored keyword gate rather than a prefix.
package writer

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.writer.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,128})\b`)

// minEntropy rejects low-information 40-128 char runs that clear the bare
// alnum regex but are not key-grade randomness (repeated-character padding,
// placeholders, structured IDs). Writer.com does not publish an authoritative
// key prefix/length/charset, so the token shape cannot be narrowed; 3.0 is the
// conservative recall-safe floor (a stricter 3.5 would risk culling real keys
// whose charset is undocumented).
const minEntropy = 3.0

// keywordRe is the anchored Writer.com marker. The bare `writer`
// substring is everywhere in source code (`io.Writer`, `bufio.Writer`,
// `WriteCloser`, `receive_pack writer` etc.) and pairs with any
// adjacent 40-char alnum run — git SHAs, base64 chunks. Require a
// Writer.com credential anchor.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bwriter[_\-](?:api|token|key|secret)` +
	`|\bwriter\.com\b` +
	`|\bapi\.writer\.com\b` +
	`|\bwriter[ \t]*[:=]` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Writer }

func (Scanner) Keywords() []string { return []string{"writer"} }

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
		// Entropy gate: structured/low-information 40-128 char runs (repeated
		// characters, padded placeholders) clear the alnum regex but are not
		// random tokens — reject them even when near the keyword.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Writer,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/models", nil)
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
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
