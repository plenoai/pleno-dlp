// Package vimeo detects Vimeo OAuth2 access tokens issued from the developer
// dashboard. Verified via /me on api.vimeo.com with Bearer auth — read-only
// and confirms the user the token is bound to.
//
// Token format: Vimeo does NOT publish an authoritative spec for the access
// token's prefix, length, or charset. Its developer docs describe the value
// only as "a unique code" (https://developer.vimeo.com/api/authentication),
// and there is no upstream trufflehog vimeo detector to mirror. Because the
// format is undocumented, the token regex is left as a generic 32-128 alnum
// run and recall is preserved by NOT pinning a length. False positives are
// instead suppressed by (1) a conservative Shannon-entropy floor and (2) an
// assignment-anchored keyword arm regex within a tight radius. If Vimeo ever
// documents a prefix/length, anchor on it and drop the entropy floor.
package vimeo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.vimeo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe is intentionally generic: Vimeo's token length/charset is
// undocumented (see package doc), so pinning a length would silently destroy
// recall. Disambiguation is done by the entropy floor and the arm regex.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

// minEntropy rejects low-information 32-128 char alnum runs (padded
// placeholders, repeated/structured strings) that clear the regex but are not
// random tokens. 3.0 is conservative — kept low because the documented token
// charset is unknown and an aggressive floor would over-cull real tokens.
const minEntropy = 3.0

// armRe replaces a bare strings.Contains("vimeo") window: a lone "vimeo"
// substring matched URLs, video embeds, and prose. The assignment shape
// vimeo[_-]?(api[_-]?)?(token|key|secret|client) is what a real credential
// declaration or config key looks like. The bare "vimeo" keyword stays in
// Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)vimeo[_\-]?(api[_\-]?)?(token|key|secret|client)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vimeo }

func (Scanner) Keywords() []string { return []string{"vimeo"} }

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
			DetectorType: detectors.Vimeo,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.vimeo.*+json;version=3.4")

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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
