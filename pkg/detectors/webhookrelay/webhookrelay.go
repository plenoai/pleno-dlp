// Package webhookrelay detects WebhookRelay token key + secret pairs —
// `key`/`secret` UUID-shaped near the `webhookrelay` keyword. Verified
// via /v1/tokens on my.webhookrelay.com using HTTP Basic auth.
package webhookrelay

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://my.webhookrelay.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var idRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

var contextKeywords = []string{"webhookrelay", "relay_key", "relay_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.WebhookRelay }

func (Scanner) Keywords() []string { return []string{"webhookrelay"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := idRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	tokens := make([]string, 0, len(hits))
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		tokens = append(tokens, string(data[h[2]:h[3]]))
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i := 0; i < len(tokens); i++ {
		for j := 0; j < len(tokens); j++ {
			if i == j || tokens[i] == tokens[j] {
				continue
			}
			pair := tokens[i] + ":" + tokens[j]
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.WebhookRelay,
				Raw:          []byte(tokens[i]),
				RawV2:        []byte(pair),
				Redacted:     redact(tokens[i]),
			}
			if verify {
				v, err := s.verifyPair(ctx, tokens[i], tokens[j])
				res.Verified = v
				res.VerificationErr = err
			}
			out = append(out, res)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, key, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/tokens", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)
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
