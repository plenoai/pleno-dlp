// Package gainsight detects Gainsight customer-success API access keys
// near the `gainsight` keyword. Verified via /v1/users/me on
// api.gainsightcloud.com with an Accesskey header (Gainsight's standard
// auth header — distinct from Authorization Bearer).
package gainsight

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.gainsightcloud.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Gainsight's REST API access key is an opaque, tenant-scoped credential
// passed in the `Accesskey` header. Gainsight's own auth docs decline to
// document its length or charset (it is treated as an opaque string); the
// one concrete value surfaced in the support docs is a UUID-v4 shape
// (e.g. <UUID-V4-TOKEN>). Because no authoritative source pins the
// length/charset, we do NOT narrow the regex to a fixed length — that
// would risk silently destroying recall on non-UUID shapes. We keep the
// loose 32-64 alnum candidate regex (which still covers a dash-stripped
// UUID) and lean on the entropy floor + tightened arm-regex keyword gate
// to suppress false positives.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy rejects low-information runs (aaaa…, zero-padding) that the
// bare alnum regex would otherwise admit. 3.0 is the conservative hex
// floor (a UUID-without-dashes is hex, ceiling ≈ 4.0); we do NOT use 3.5
// because a hex-only key would be over-culled.
const minEntropy = 3.0

// armRe is the assignment-anchor keyword gate. It replaces a bare
// strings.Contains(window, "gainsight") so that the mere word "gainsight"
// in unrelated prose no longer arms a high-entropy candidate.
var armRe = regexp.MustCompile(`(?i)gainsight[_\-]?(api[_\-]?)?(access[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GainSight }

func (Scanner) Keywords() []string { return []string{"gainsight"} }

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
			DetectorType: detectors.GainSight,
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

// nearKeyword reports whether a `gainsight[_-]?(api[_-]?)?(access[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby GAINSIGHT_API_KEY reference still
// arms. Radius is 64 (tightened from 256) so a stray "gainsight" mention
// far from the token no longer arms a high-entropy false positive.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Accesskey", secret)
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
