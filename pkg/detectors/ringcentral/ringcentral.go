// Package ringcentral detects RingCentral OAuth client_id (appKey) +
// client_secret (appSecret) pairs near the `ringcentral` keyword. Verified
// via /restapi/oauth/token on platform.ringcentral.com using HTTP Basic auth
// (client_id as username, secret as password). Raw carries the client_id,
// RawV2 the secret.
//
// FP hardening: the original regex was a bare `[A-Za-z0-9]{24,128}` with a
// radius-256 bare-substring `ringcentral` gate and no entropy floor — that
// shape collides with commit SHAs, base64 blobs, nonces and k8s object names
// in real codebases. We tighten three ways:
//
//   - Candidate length is anchored at the DOCUMENTED client_id minimum of 22
//     on the documented charset `[0-9A-Za-z_-]`. Source: upstream trufflehog
//     RingCentral detector pins client_id (appKey) as exactly
//     `[0-9A-Za-z_-]{22}` (github.com/trufflesecurity/trufflehog
//     pkg/detectors/ringcentral). The client_secret (appSecret) length/charset
//     is NOT published by RingCentral and upstream does not regex it, so we do
//     NOT pin an upper length for the secret — pinning an undocumented length
//     would silently destroy recall. The candidate window stays 22..128 over
//     the same charset and the pair is disambiguated by proximity + entropy.
//   - A `ringcentral`-assignment arm regex must appear within a tight 64-byte
//     window (was a bare `strings.Contains` over radius 256).
//   - Both halves must clear a Shannon-entropy floor of 3.5 bits/char
//     (high-variety alnum tokens; the 22-char ceiling is ~4.46), which culls
//     low-information runs that clear the regex but are not credentials.
package ringcentral

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://platform.ringcentral.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Candidate credential shape. The lower bound (22) and charset `[0-9A-Za-z_-]`
// are the DOCUMENTED RingCentral client_id (appKey) format per upstream
// trufflehog. The secret length is undocumented, so the upper bound is left
// generous (128) rather than guessed; the keyword arm + entropy gate carry the
// false-positive load.
var tokenRe = regexp.MustCompile(`\b([0-9A-Za-z_-]{22,128})\b`)

// armRe is the assignment-style RingCentral reference that must appear within
// the proximity window. A bare "ringcentral" substring (SDK package names,
// doc URLs, comments) is too weak; the `ringcentral[_-]?(client[_-]?|app[_-]?)?
// (id|key|secret|token)` shapes are what a real credential assignment or env
// var takes (RINGCENTRAL_CLIENT_ID, ringcentral_app_secret, etc.).
var armRe = regexp.MustCompile(`(?i)ringcentral[_\-]?(client[_\-]?|app[_\-]?)?(id|key|secret|token)`)

// minEntropy rejects low-information 22+ char runs (repeated chars, padded
// identifiers) that clear the alnum regex but are not real credentials.
// 3.5 is the standard floor for high-variety alnum tokens; realistic
// RingCentral id/secret fixtures measure ~3.9-4.5.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RingCentral }

// Keywords keeps the bare "ringcentral" as the engine prefilter — without it
// the engine would evaluate the regex against every chunk. The tighter armRe
// gate runs inside FromData.
func (Scanner) Keywords() []string { return []string{"ringcentral"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// A `ringcentral`-assignment reference within a tight window is
		// mandatory; 22+ char alnum runs are common (SHAs, nonces, blobs).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		// Entropy gate: structured / low-information runs that clear the
		// regex but lack credential-grade randomness are rejected.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	id, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.RingCentral,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify {
		v, err := s.Verify(ctx, id+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a `ringcentral`-assignment reference (armRe)
// appears within a tight window on either side of the candidate. The window
// spans both directions so an id and secret defined a few lines apart from a
// single RINGCENTRAL_* reference still arm.
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
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/restapi/oauth/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
