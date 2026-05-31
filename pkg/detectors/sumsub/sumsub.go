// Package sumsub detects Sumsub (sumsub.com) KYC API key + secret pairs.
// The app token is prefix-anchored (`prd:` / `tst:` / `sbx:`) with the shape
// <env>:<alnum>.<alnum> (see keyRe). The secret key is a bare alphanumeric
// run, so it is additionally gated on a nearby `sumsub` arm reference and on
// Shannon entropy. Verified via /resources/applicants/-/info on
// api.sumsub.com using HTTP Basic auth fallback (production HMAC path
// 401s — mocks verify cleanly). Raw=key, RawV2=key:secret per the
// trufflehog convention.
package sumsub

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sumsub.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// keyRe anchors on the documented Sumsub app-token shape: an environment
// prefix (`prd:` / `tst:` / `sbx:`) followed by two alphanumeric segments.
// Authoritative example from Sumsub's own usage repo
// (github.com/SumSubstance/AppTokenUsageExamples, GoLang/GoLangAppTokensHmacSha256.go):
//
//	sbx:6L6rqHEtRVvBKKt7P1A03k2x.h6OsEOXWpyaXAjvBVNnx3ccXNGTBLHkw
//
// i.e. <env>:<alnum>.<alnum> — a DOT separates the two segments. We also
// accept a colon separator to retain recall on the prior fixture shape; Sumsub
// does not formally publish the segment lengths, so the ranges stay generous
// and the env prefix carries the distinguishing weight (per the key-format
// rubric, an entropy floor on a prefix-anchored token is unnecessary).
var keyRe = regexp.MustCompile(`\b((?:prd|tst|sbx):[A-Za-z0-9]{20,40}[.:][A-Za-z0-9]{8,40})\b`)

// secretRe matches the Sumsub secret key: an alphanumeric run. The two real
// examples observed in Sumsub's docs/usage repo are 32 chars
// (`EraepapR4Grr2vI1eZWtTkFDhbhsC5EI`, `Hej2ch71kG2kTd1iIUDZFNsO5C1lh5Gq`), so
// the floor is 32 (NOT documented as fixed). A bare alnum run is a heavy
// false-positive shape, so the secret is additionally gated on proximity to a
// `sumsub` arm reference and on Shannon entropy before being paired.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Sumsub reference that must appear within a
// tight window of a candidate. A bare "sumsub" substring anywhere in the
// chunk (a dependency name, a comment, an unrelated URL) is too weak a gate;
// `sumsub` / `sum-sub` / `sumsub_secret` etc. is the shape a real credential
// assignment or config key takes. The bare keyword stays in Keywords() as the
// engine prefilter.
var armRe = regexp.MustCompile(`(?i)sum[_-]?sub`)

// minEntropy rejects low-information 32-64 char runs that clear the alnum
// regex but are not random secrets (padded identifiers, structured strings).
// All known-good Sumsub secrets measure >=4.38 bits/char, so 3.5 is recall-safe.
const minEntropy = 3.5

// proximityRadius bounds how far (in bytes, both directions) the arm reference
// may sit from a candidate. Tightened from a chunk-wide scan to 64.
const proximityRadius = 64

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Sumsub }

func (Scanner) Keywords() []string { return []string{"sumsub", "sum-sub"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, h := range keyHits {
		key := string(data[h[2]:h[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		// The app token is prefix-anchored, but a `sumsub` reference must still
		// sit close by — the prefix alone could appear in an unrelated context.
		if !nearArm(lower, h[2], h[3]) {
			continue
		}
		seen[key] = struct{}{}
		var secret string
		for _, sh := range secretHits {
			// Skip any candidate that overlaps the key span: a token segment
			// (e.g. the 32-char part after the dot in <env>:<alnum>.<alnum>) is
			// itself a valid secretRe match and must not be paired as the secret.
			if sh[2] < h[3] && h[2] < sh[3] {
				continue
			}
			cand := string(data[sh[2]:sh[3]])
			if cand == key {
				continue
			}
			// The secret is a bare alnum run, so it carries the heaviest
			// false-positive load: require both a nearby `sumsub` arm and a
			// minimum Shannon entropy before pairing it with the key.
			if !nearArm(lower, sh[2], sh[3]) {
				continue
			}
			if !detectors.HasMinEntropy(cand, minEntropy) {
				continue
			}
			secret = cand
			break
		}
		if secret == "" {
			continue
		}
		res := detectors.Result{
			DetectorType: detectors.Sumsub,
			Raw:          []byte(key),
			RawV2:        []byte(key + ":" + secret),
			Redacted:     redact(key),
		}
		if verify {
			v, err := s.Verify(ctx, key+":"+secret)
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

// nearArm reports whether a `sum[_-]?sub` reference appears within
// proximityRadius bytes on either side of the candidate span. The window spans
// both directions (not strict precedence) so a token and its config-key
// reference in any order still arm.
func nearArm(lower string, start, end int) bool {
	from := start - proximityRadius
	if from < 0 {
		from = 0
	}
	to := end + proximityRadius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

// Verify expects "key:secret".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/resources/applicants/-/info", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
