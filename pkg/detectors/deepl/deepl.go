// Package deepl detects DeepL API keys (UUID-shaped + optional `:fx`
// suffix marking the free tier). Verified via /v2/usage on
// api-free.deepl.com (or api.deepl.com for Pro) with the Authorization
// `DeepL-Auth-Key` header.
package deepl

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api-free.deepl.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// DeepL Free key: 36-char UUID + ":fx" suffix.
// DeepL Pro key: 36-char UUID, identical shape to many UUIDs, so we
// require the keyword "deepl" nearby for the bare-UUID case.
var tokenRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?::fx)?)\b`)

var contextKeywords = []string{"deepl"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DeepL }

func (Scanner) Keywords() []string { return []string{"deepl"} }

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
		// The bare UUID half (no :fx) collides with arbitrary UUIDs;
		// require the keyword. The :fx-suffixed shape is unique enough
		// to surface unconditionally.
		if !strings.HasSuffix(token, ":fx") && !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.DeepL,
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
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 128
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/usage", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "DeepL-Auth-Key "+secret)
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
