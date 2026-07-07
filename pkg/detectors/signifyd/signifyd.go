// Package signifyd detects Signifyd API key + team id pairs near the
// `signifyd` keyword. Paired credential — Raw=teamId,
// RawV2=teamId+":"+apiKey. Verified via HTTP Basic auth (apiKey + ":")
// on api.signifyd.com /v3/teams.
package signifyd

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.signifyd.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,80})\b`)

// armRe is the assignment-style Signifyd reference that must appear within the
// proximity window. A bare "signifyd" substring is too weak a gate against a
// generic 20-80 char alphanumeric run. No authoritative source documents the
// API key's length or charset (Signifyd's own apiary blueprint only shows
// placeholder keys such as `abcdefghijklmnopqrstuvwxyz`), so we do NOT pin a
// length and instead arm on `signifyd[_-]?(api[_-]?)?(token|key|secret)` —
// the shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)signifyd[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative floor that rejects low-entropy 20-80 char runs
// which clear the alnum regex but are not random tokens. 3.0 (not 3.5)
// because the documented charset is unknown; a tighter floor risks culling
// real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Signifyd }

func (Scanner) Keywords() []string { return []string{"signifyd"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var ident, token string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 20-80 char runs clear the
		// alnum regex but are not random credentials — reject them even when
		// armed.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		if ident == "" {
			ident = v
			continue
		}
		if v == ident {
			continue
		}
		token = v
		break
	}
	if ident == "" || token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Signifyd,
		Raw:          []byte(ident),
		RawV2:        []byte(ident + ":" + token),
		Redacted:     redact(ident),
	}
	if verify {
		v, err := s.Verify(ctx, ident+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a `signifyd[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions so a key and secret defined alongside a nearby
// SIGNIFYD_API_KEY reference still arm.
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	_, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3/teams", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(tok + ":"))
	req.Header.Set("Authorization", "Basic "+auth)
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
