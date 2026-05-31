// Package modeanalytics detects Mode Analytics API token + secret
// pairs near the `mode` keyword. Paired credential per the trufflehog
// convention — Raw=token, RawV2=token+":"+secret. Verified via HTTP
// Basic auth on app.mode.com /api/account.
//
// Mode's documented credentials are lowercase hex (Discovery API
// signature-token access_key/access_secret are 24 hex chars), so the
// candidate regex is hex-restricted with a conservative entropy floor and a
// tight assignment-anchored keyword gate rather than the broad alnum match
// it carried before. See https://mode.com/developer/discovery-api/signature-tokens/
package modeanalytics

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.mode.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches Mode's hex credential halves. Mode's documented credentials
// (Discovery API signature-token `access_key`/`access_secret`) are lowercase
// hex — e.g. access_key "8b6fdc0a36bf340604a3cedc" / access_secret
// "829146cb6c752f51bbbb8c85", both 24 hex chars
// (https://mode.com/developer/discovery-api/signature-tokens/). Only the
// signature-token length (24) is documented; Workspace/Member/personal token
// lengths are not, so we keep a hex-restricted {16,64} range rather than
// pinning a single length — restricting the charset from the old broad
// [A-Za-z0-9] alnum to hex alone already removes the bulk of the base62 noise.
var tokenRe = regexp.MustCompile(`\b([a-fA-F0-9]{16,64})\b`)

// minEntropy rejects structured/low-information hex runs (zero-padded ids,
// repeated-nibble placeholders) that clear the hex regex but are not real
// credentials. Hex caps near 3.6 bits/char and the documented 24-hex examples
// sit around 3.3, so 3.5 would over-cull real keys; 3.0 is the hex-safe floor.
const minEntropy = 3.0

// armRe is the assignment-style Mode reference that must appear within the
// proximity window. A bare strings.Contains for "mode.com"/"modeanalytics"
// over a 256-char radius armed on script-src URLs and doc links; the
// `mode[_-]?(analytics|api|access)?[_-]?(api[_-]?)?(token|key|secret)` shape is
// what a real credential assignment or config key takes — including Mode's own
// `access_key`/`access_secret` naming from the Discovery API docs. The bare
// keywords stay in Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)mode[_\-]?(analytics|api|access)?[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ModeAnalytics }

func (Scanner) Keywords() []string { return []string{"mode_analytics", "modeanalytics", "mode.com"} }

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
		// Reject low-information hex runs (zero-padded ids, repeated nibbles)
		// that clear the hex regex but are not credential-grade.
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
		DetectorType: detectors.ModeAnalytics,
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

// nearKeyword reports whether an armRe Mode-credential reference appears within
// a tight window on either side of the candidate. Radius tightened 256->64 to
// keep the credential assignment and its key on the same logical line.
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
	ident, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/account", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(ident + ":" + tok))
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
