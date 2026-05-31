// Package idnow detects IDnow KYC API tokens (32-64 alphanumeric).
// Surface only when an `idnow` keyword is in the same chunk to keep the
// generic alphanumeric shape from triggering universally. Verified via
// /api/v1/identifications on gateway.idnow.de with the X-API-KEY header.
//
// Credential format: IDnow does not publish the prefix/length/charset of
// the apiKey value (sent as {"apiKey": "<TOKEN>"} to /api/v1/{customer}/login).
// Every reachable reference is a placeholder ("1234api_key", "API-KEY-TOKEN");
// the only documented length/charset constraints in the IDnow docs apply to
// transaction identifiers (UUIDv4, [a-zA-Z0-9_-], max 255), not the apiKey.
// Trufflehog ships no idnow detector to mirror. With no authoritative format,
// the bare [A-Za-z0-9]{32,64} shape is left UNCHANGED (narrowing it would
// guess at a length and silently destroy recall); FP risk is reduced only by
// recall-safe gate-tightening: an assignment-anchor arm regex, a tightened
// radius, and a conservative entropy floor.
package idnow

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://gateway.idnow.de"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Generic alphanumeric shape — no documented prefix/length, so the gate
// (arm regex + entropy + radius) does the disambiguation, not the regex.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe replaces the bare strings.Contains(window,"idnow"): it requires an
// assignment-style context (idnow_api_key / idnow-token / idnow secret) so a
// stray "idnow" mention in prose no longer arms the detector. The bare
// keyword stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)idnow[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32-64 char runs (repeated/structured
// strings) that clear the regex but lack credential-grade randomness. Held
// conservative at 3.0 because no source documents the charset; a higher floor
// would risk culling real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.IDnow }

func (Scanner) Keywords() []string { return []string{"idnow"} }

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
			DetectorType: detectors.IDnow,
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
	window := lower[from:to]
	return armRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/identifications", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-KEY", secret)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
