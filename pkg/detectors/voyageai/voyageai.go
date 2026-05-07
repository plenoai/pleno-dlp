// Package voyageai detects Voyage AI API keys (`pa-<base64url>`) and
// verifies them against /v1/embeddings with Bearer auth.
//
// The `pa-` prefix is shared with a few other providers' tokens, so we
// gate on a `voyage` keyword in a 256-byte window.
package voyageai

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.voyageai.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// pa- + 24+ base64url chars. Production keys are typically 35 chars total.
var keyRe = regexp.MustCompile(`\b(pa-[A-Za-z0-9_-]{24,})\b`)

var contextKeywords = []string{"voyage", "voyageai", "voyage_api", "voyage_key"}

// probeBody is the smallest legal /v1/embeddings request — single short
// input, voyage-3-lite is the cheapest model.
var probeBody = []byte(`{"input":["x"],"model":"voyage-3-lite"}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.VoyageAI }

func (Scanner) Keywords() []string { return []string{"voyage"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.VoyageAI,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v1/embeddings", bytes.NewReader(probeBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
