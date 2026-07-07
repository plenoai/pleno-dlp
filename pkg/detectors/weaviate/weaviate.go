// Package weaviate detects Weaviate Cloud admin API keys (64-char base62
// near `weaviate`) and verifies them against the cluster's /v1/meta with
// Bearer auth.
//
// The shape collides with sha256-style digests, so co-occurrence with
// `weaviate` in a 256-byte window is mandatory. Verification requires a
// cluster URL — when absent we surface unverified rather than probe a
// hard-coded host.
package weaviate

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{64})\b`)

var contextKeywords = []string{"weaviate", "weaviate_api", "weaviate_key", "weaviate_admin"}

// hostRe extracts a *.weaviate.cloud or *.weaviate.network URL from a
// 256-byte window — the only way we can verify without configuration.
var hostRe = regexp.MustCompile(`https?://[a-zA-Z0-9.-]+\.weaviate\.(?:cloud|network)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Weaviate }

func (Scanner) Keywords() []string { return []string{"weaviate"} }

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
			DetectorType: detectors.Weaviate,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			host := nearestHost(data, h[2])
			if host == "" {
				// No cluster URL in chunk — can't verify, but the key
				// shape + keyword still warrants the hit.
				res.VerificationErr = nil
			} else {
				v, err := verifyWith(ctx, host, token)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify with a colon-joined host:token form so the trufflehog single-secret
// Verifier interface still works.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, token, ok := strings.Cut(secret, "|")
	if !ok {
		return false, nil
	}
	return verifyWith(ctx, host, token)
}

func verifyWith(ctx context.Context, host, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/v1/meta", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func nearestHost(data []byte, pos int) string {
	const radius = 1024
	from := pos - radius
	if from < 0 {
		from = 0
	}
	to := pos + radius
	if to > len(data) {
		to = len(data)
	}
	if m := hostRe.Find(data[from:to]); m != nil {
		return string(m)
	}
	return ""
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
