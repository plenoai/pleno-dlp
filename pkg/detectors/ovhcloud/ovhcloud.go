// Package ovhcloud detects OVH Cloud API credentials. OVH issues a
// (application_key, application_secret, consumer_key) triple per
// integration. Verification is infeasible: a single call to OVH's API
// requires the full triple plus an HMAC-SHA1 signature
// ($1$ + SHA1(app_secret + "+" + consumer_key + "+" + method + "+" + url
// + "+" + body + "+" + timestamp)) with X-Ovh-Application carrying the
// app_key. With only one of the three components in hand no request can
// be signed, so any Verify path would constantly return Verified=false.
// The detector is therefore unverified-by-design (class b).
//
// FromData emits a single matched 32-char token as Result.Raw (no RawV2,
// no ExtraData): the on-disk shapes of application_key / application_secret
// / consumer_key are indistinguishable, so we cannot reliably pair them.
package ovhcloud

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// OVH application/consumer keys are documented as mixed-case 32-char alnum
// tokens. A delimiter (=, :, quote or whitespace) must immediately precede
// the token so we anchor on an assigned value rather than any arbitrary
// 32-char run embedded in a larger word.
var keyRe = regexp.MustCompile(`[=:"'\s]([A-Za-z0-9]{32})\b`)

// pure 32-char lowercase hex — the dominant false-positive class
// (MD5 digests, hyphen-stripped UUIDs, hex32 session ids). Real OVH keys
// are mixed-case, so excluding all-lowercase-hex loses no true positives.
var lowerHex32Re = regexp.MustCompile(`^[0-9a-f]{32}$`)

// contextKeywords are OVH-SPECIFIC. The bare generic "consumer_key"
// (a stock OAuth1 / Twitter field) is intentionally NOT here — it stays a
// coarse Keywords() prefilter only, never a sufficient proximity match.
// Bare "ovh" is also dropped in favor of qualified forms to avoid
// incidental substring hits.
var contextKeywords = []string{
	"ovhcloud",
	"ovh_application_key",
	"ovh_application_secret",
	"ovh_consumer_key",
	"ovh_consumer",
	"ovh_application",
	"application_key",
	"application_secret",
	"x-ovh-application",
}

// proximity radius for the context-keyword vicinity check. Kept tight so a
// generic field plus an unrelated 32-char digest hundreds of bytes away no
// longer co-qualifies.
const vicinityRadius = 64

// tokenMinEntropy gates out low-entropy structured 32-char strings
// (sequential ids, letter/zero-padded values) that the broad shape regex
// would otherwise accept. ~3.0 bits/char is the sane floor for alnum runs.
const tokenMinEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OVHCloud }

// Keywords is a coarse chunk prefilter only. "consumer_key" lives here so
// the engine still surfaces OAuth1-shaped chunks for inspection, but it is
// deliberately absent from contextKeywords (the precise proximity gate).
func (Scanner) Keywords() []string { return []string{"ovh", "ovhcloud", "consumer_key"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// capture group 1 is the token; h[2]:h[3] are its bounds.
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !plausibleKey(token) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.OVHCloud,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// plausibleKey rejects the false-positive shapes that share the 32-char
// alnum alphabet with a real OVH key.
func plausibleKey(token string) bool {
	if lowerHex32Re.MatchString(token) {
		return false // MD5 digest / hyphen-stripped UUID / hex32 id
	}
	if !detectors.HasMinEntropy(token, tokenMinEntropy) {
		return false // sequential / padded / repeated-char structured id
	}
	return true
}

func nearKeyword(lower string, start, end int) bool {
	from := start - vicinityRadius
	if from < 0 {
		from = 0
	}
	to := end + vicinityRadius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
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
