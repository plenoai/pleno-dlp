// Package lambdalabs detects Lambda Labs Cloud API keys — 40+ char
// alphanumeric strings near a Lambda Labs reference. Verified via
// /api/v1/instance-types on cloud.lambdalabs.com using HTTP Basic auth with
// the key as the username (no password) — the documented auth scheme is
// `curl -u <TOKEN>: https://cloud.lambdalabs.com/api/v1/...`.
//
// No authoritative source documents the Lambda Cloud API key's prefix,
// length, or charset: the official Cloud API reference and OpenAPI spec
// describe only the Basic-auth scheme and use `API-KEY` / `xxx` placeholders
// in every example, and trufflehog ships no upstream lambdalabs detector to
// mirror. We therefore do NOT pin a length and apply recall-safe gate
// tightening only: a `lambdalabs[_-]?(api[_-]?)?(token|key|secret)`-style
// assignment anchor within a tight 64-byte window plus a conservative Shannon
// entropy floor. The bare keyword stays in Keywords() as the engine prefilter.
package lambdalabs

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://cloud.lambdalabs.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 40+ alphanumeric. No documented prefix or fixed length to anchor on, so the
// arm regex and entropy floor carry the false-positive load. The {40,} bound
// is the pre-existing recall-safe shape — we keep it because no source pins a
// length, and tightening it would silently destroy recall.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,})\b`)

// armRe is the assignment-style Lambda Labs reference that must appear within
// the proximity window. A bare "lambdalabs" substring (doc URLs, dependency
// names, comments) is too weak to gate a generic 40+ char alphanumeric run;
// the `lambdalabs[_-]?(api[_-]?)?(token|key|secret)` shape is what a real
// assignment or config key takes (e.g. LAMBDALABS_API_KEY).
var armRe = regexp.MustCompile(`(?i)lambda[_\-]?labs[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 40+ char runs that clear the alnum regex
// but are not real keys (git SHAs, padded identifiers). 3.0 is the
// conservative floor used when no authoritative charset is documented — a
// higher floor risks culling valid lower-variety keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LambdaLabs }

func (Scanner) Keywords() []string { return []string{"lambdalabs", "lambda_labs", "lambda-labs"} }

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
		// Entropy gate: low-information 40+ char runs (git SHAs, padded
		// identifiers) that clear the regex but lack key-grade randomness are
		// rejected. Conservative 3.0 floor — no documented charset to justify
		// a higher cut.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// An assignment-style Lambda Labs reference within a tight window is
		// mandatory — 40+ char alphanumerics are common (hashes, base64 runs).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.LambdaLabs,
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

// nearKeyword reports whether an armRe-style Lambda Labs reference appears
// within a tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a key defined alongside a
// nearby LAMBDALABS_API_KEY reference still arms. Radius tightened 256->64 to
// cut cross-line false positives.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/instance-types", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
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
