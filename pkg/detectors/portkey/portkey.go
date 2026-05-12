// Package portkey detects Portkey (portkey.ai) AI-gateway API keys
// (43-50 char base64url) near the `portkey` keyword. Verified via /v1
// on api.portkey.ai with x-portkey-api-key header.
package portkey

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.portkey.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Portkey API keys are 32-64 base64url chars, anchored on `portkey`.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9+/_=-]{32,64})\b`)

// keywordRe is the anchored Portkey.ai marker. The bare `portkey`
// substring matches inside other words (`ExportKey`, `importKey`),
// so word-bounded `\bportkey\b` plus credential anchors are required.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bportkey[_\-](?:api|token|key|secret)` +
	`|\bportkey\.ai\b` +
	`|\bapi\.portkey\.ai\b` +
	`|\bx-portkey-api-key\b` +
	`|\bportkey[ \t]*[:=]` +
	`|\bportkey\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Portkey }

func (Scanner) Keywords() []string { return []string{"portkey"} }

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
			DetectorType: detectors.Portkey,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/virtual-keys", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-portkey-api-key", secret)
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
