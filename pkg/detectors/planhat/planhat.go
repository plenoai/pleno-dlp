// Package planhat detects Planhat customer-success tenant tokens near
// the `planhat` keyword. Unverified by design — Planhat uses per-tenant
// hosts (`<tenant>.planhat.com`), so verify only fires when an apiBase
// override is supplied. Canonical probe is /api/users/me with
// Authorization Bearer.
package planhat

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Planhat does not publish an authoritative token length/charset/prefix
// (no upstream trufflehog detector exists; the developer docs describe how
// to generate API Access Tokens but never document the credential shape).
// We therefore keep the pre-existing alnum length window unchanged — pinning
// a narrower length would be an unsourced guess that silently kills recall —
// and lean on the assignment-anchor arm regex plus a conservative entropy
// floor to bound false positives.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Planhat reference that must appear within the
// proximity window. A bare "planhat" substring (marketing URLs, dependency
// names, comments) is too weak; "planhat_token" / "planhat-api-key" /
// "planhattoken" is the shape a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)planhat[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy alnum runs that clear the regex but are not
// random tokens. Conservative 3.0 floor (not 3.5) because the credential
// charset is undocumented — over-culling would destroy recall on a real but
// lower-variety token.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Planhat }

func (Scanner) Keywords() []string { return []string{"planhat"} }

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
			DetectorType: detectors.Planhat,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/users/me", nil)
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
