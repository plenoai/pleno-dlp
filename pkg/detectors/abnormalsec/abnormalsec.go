// Package abnormalsec detects Abnormal Security API tokens near the
// `abnormal` / `abnormalsecurity` keyword. Verified via /v1/threats on
// api.abnormalplatform.com with an Authorization Bearer header.
package abnormalsec

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.abnormalplatform.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Abnormal Security tokens are alphanumeric. No authoritative source
// documents a prefix or an exact length (the provider's docs and every
// third-party integration guide call it only "a unique API access token"),
// so we keep the original 32-64 alnum range rather than pin a length we
// cannot cite — over-pinning would silently destroy recall.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// minEntropy is a conservative floor. A bare `[A-Za-z0-9]{32,64}` run with no
// documented prefix collides with commit SHAs, base32/hex blobs, and padded
// identifiers; 3.0 culls the most obviously structured runs without trimming
// genuine high-variety tokens (a 3.5 floor risks over-culling, and no source
// pins the charset tightly enough to justify it).
const minEntropy = 3.0

// armRe is the assignment-style Abnormal reference that must appear within a
// tight proximity window. A bare "abnormal" substring (prose, the word
// "abnormal", unrelated domains) is too weak a gate; the assignment shapes
// abnormal[_-]?(api[_-]?)?(token|key|secret) and the product host words are
// what a real credential reference looks like.
var armRe = regexp.MustCompile(`(?i)abnormal(security|platform)?[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AbnormalSec }

func (Scanner) Keywords() []string { return []string{"abnormal"} }

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
		// Conservative entropy gate: rejects low-information 32-64 char runs
		// (structured identifiers, padded names) that clear the regex but are
		// not random tokens.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AbnormalSec,
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

// nearKeyword reports whether an assignment-style Abnormal reference appears
// within a tight window on either side of the candidate. The window is
// searched in both directions (not strict immediate precedence) so a token
// declared alongside a nearby ABNORMAL_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/threats", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
