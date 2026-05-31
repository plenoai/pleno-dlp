// Package hetzner detects Hetzner Cloud API tokens (a bare 64-char
// alphanumeric string, no prefix) near a `hcloud` / `hetzner` keyword.
// Verified via /v1/servers on api.hetzner.cloud using Bearer auth.
//
// Format: the length is authoritatively 64 — the official
// terraform-provider-hcloud rejects any other length with
// "entered token is invalid (must be exactly 64 characters long)"
// (hcloud/provider.go ValidateFunc: `len(token) != 64`, mirrored in
// issue #149). No prefix and no charset restriction is documented; the
// provider's own validation is length-only. The detector keeps the
// existing `[A-Za-z0-9]` charset assumption (no authoritative source
// widens or narrows it) and disambiguates the otherwise-generic 64-char
// shape with an entropy floor plus an assignment-style keyword gate.
package hetzner

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.hetzner.cloud"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Hetzner Cloud API tokens are authoritatively 64 chars (length-only
// validation in terraform-provider-hcloud); charset undocumented, alnum kept.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`)

// armRe is the assignment-style Hetzner reference that must appear within the
// proximity window. A bare "hcloud"/"hetzner" substring (doc links, the
// api.hetzner.cloud host, package names like `hcloud-go`) is too weak a gate
// against a generic 64-char alphanumeric run; `(hcloud|hetzner)[_-]?...
// (token|key|secret)` is the shape a real credential assignment takes. The
// bare keywords stay in Keywords() as the cheap Aho-Corasick prefilter.
var armRe = regexp.MustCompile(`(?i)(hcloud|hetzner)[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 64-char runs (padded placeholders,
// repeated characters, structured hashes) that clear the alnum regex but lack
// key-grade randomness. A real 64-char base62 token sits well above 3.5; this
// is the rubric's "no prefix, fixed length, high-variety charset" floor.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Hetzner }

func (Scanner) Keywords() []string { return []string{"hcloud", "hetzner"} }

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
		// Entropy gate: structured/low-information 64-char runs clear the alnum
		// regex but are not random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Hetzner,
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

// nearKeyword reports whether a `(hcloud|hetzner)[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/servers?per_page=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
