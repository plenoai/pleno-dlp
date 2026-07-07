// Package jellyfish: Jellyfish publishes no authoritative prefix, length, or
// charset for its API tokens, so the regex is NOT length-pinned to a guessed
// value; recall-safe hardening does the work instead — a tightened proximity
// window, an assignment-anchor arm regex, and a conservative entropy floor.
package jellyfish

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.jellyfish.co"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Jellyfish reference that must appear within
// the proximity window: a bare "jellyfish" substring is too weak a gate
// against a generic 40-80 alphanumeric run. The bare keyword stays in
// Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)jellyfish[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor: with no authoritative charset
// documented the token could be hex-ish or low-variety, and a higher floor
// would over-cull real tokens. 3.0 rejects only the most structured
// low-information runs while preserving recall.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jellyfish }

func (Scanner) Keywords() []string { return []string{"jellyfish"} }

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Jellyfish,
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
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/endpoints/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-Key", secret)
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
