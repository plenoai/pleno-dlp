// Package gandi detects Gandi (domain registrar) API credentials — a generic
// 24-80 char alphanumeric run gated by an assignment-style `gandi_(api_)?key`
// reference within a 64-char window plus a 3.0 entropy floor. Gandi publishes
// no authoritative prefix/length/charset for either the deprecated `Apikey` or
// the current PAT `Bearer` credential, so no length is pinned. Verified via
// /v5/organization/organizations on api.gandi.net using the documented
// `Authorization: Apikey <key>` header.
package gandi

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.gandi.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Gandi credentials (deprecated `Apikey` and current PAT `Bearer`) have no
// authoritatively documented prefix, length, or charset — the official auth
// doc shows only illustrative placeholders (`Apikey 0123456`, `Bearer abc`)
// and there is no upstream trufflehog detector to mirror. So the shape stays a
// generic alphanumeric run and the false-positive load is carried entirely by
// the assignment-anchor arm regex, a tight proximity window, and an entropy
// floor — no length is pinned, to avoid silently destroying recall.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,80})\b`)

// armRe is the assignment-style Gandi reference that must appear within the
// proximity window. A bare "gandi" substring (package names, docs URLs,
// comments) is too weak; `gandi[_-]?(api[_-]?)?(token|key|secret)` is the shape
// a real credential assignment or config key takes (gandi_api_key, gandi-token,
// gandiapikey, gandi_secret, ...). The bare "gandi" keyword still serves as the
// engine prefilter via Keywords().
var armRe = regexp.MustCompile(`(?i)gandi[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information alphanumeric runs that clear the regex but
// are not random credentials (structured identifiers, padded names, slugs).
// Conservative 3.0 floor: no documented charset to justify the 3.5 high-variety
// threshold, and 3.0 still admits hex-shaped values (hex caps ~3.6).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Gandi }

func (Scanner) Keywords() []string { return []string{"gandi"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: reject structured/low-information runs that arm on a
		// nearby reference but are not random credentials.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Gandi,
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

// nearKeyword arms only when an assignment-style Gandi credential reference
// (armRe) appears within a tight window around the candidate. Radius is 64
// (down from 256): a real `gandi_api_key = <value>` puts the reference adjacent
// to the token, while a wider window readmits unrelated "gandi" mentions.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v5/organization/organizations", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Apikey "+secret)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
