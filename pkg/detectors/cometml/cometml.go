// Package cometml detects Comet ML (comet.com) API keys (32-100 alnum)
// near a comet api/key/token/secret cue. Verified via
// /api/rest/v2/account-details on www.comet.com with Authorization header.
//
// No authoritative source documents the API key length or charset (the
// "32-50 alphanumeric" spec circulating online describes Comet's
// experiment_key, not the API key), so the alnum-range regex is left intact
// and recall is protected with gate-tightening only: a radius-64
// assignment-anchored keyword arm plus a conservative entropy floor.
package cometml

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://www.comet.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,100})\b`)

// minEntropy is a conservative floor. No authoritative source documents the
// Comet API key charset, so we cannot assume a high-variety distribution;
// 3.0 only rejects degenerate runs (repeated chars, low-cardinality fillers)
// that clear the bare alnum regex without over-culling real keys.
const minEntropy = 3.0

// armRe is the windowed keyword gate. It replaces a bare radius-256
// strings.Contains over the prefilter keywords with an assignment-anchored
// arm: the keyword must appear adjacent to an api/token/key/secret cue, which
// kills incidental "comet.com" URLs and prose mentions sitting near any
// high-entropy alnum blob. The bare keywords stay in Keywords() as the
// engine prefilter.
var armRe = regexp.MustCompile(`(?i)comet[._-]?(ml)?[._-]?(api[._-]?)?(key|token|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CometML }

func (Scanner) Keywords() []string {
	return []string{"comet_api_key", "comet-api-key", "cometml", "comet_ml", "comet.ml", "comet.com"}
}

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
		// Entropy gate: reject degenerate low-cardinality runs that clear the
		// alnum regex but lack key-grade randomness.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.CometML,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/rest/v2/account-details", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", secret)
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
