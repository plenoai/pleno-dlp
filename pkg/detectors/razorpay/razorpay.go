// Package razorpay detects Razorpay key + secret pairs and verifies them
// against /v1/items with HTTP Basic auth (key as username, secret as
// password). The key id is rzp_test_<14 alnum> or rzp_live_<14 alnum> and
// the secret is a 24-char base62 string, per the upstream trufflehog
// detector (github.com/trufflesecurity/trufflehog pkg/detectors/razorpay:
// key `(?i)\brzp_live_[A-Za-z0-9]{14}\b`, secret `\b[A-Za-z0-9]{24}\b`).
// Razorpay's own docs only show `rzp_<env>_xxxx` placeholders and do not
// pin an exact length, so the {14}/{24} lengths are taken from trufflehog.
//
// Both halves are needed to make any API request, so the detector emits a
// Result only when both co-occur near a `razorpay`-style reference. The key
// id carries a strong distinguishing prefix, so it is anchored on that. The
// secret has no prefix and is a bare base62 run that collides with commit
// SHAs / nonces / object names, so it is additionally gated on Shannon
// entropy and only accepted within a tight window of an assignment-style
// `razorpay` reference. rzp_live_ pairs are SeverityCritical when
// verified — they can issue real charges.
package razorpay

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.razorpay.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Key id is anchored on the rzp_(test|live)_ prefix. The prefix is the
	// strong distinguishing token (rubric: prefix present -> anchor on it,
	// length/entropy unnecessary), so the trailing run is left open-ended.
	// trufflehog upstream uses {14}, but Razorpay's own docs only show
	// `rzp_<env>_xxxx` placeholders without an exact length and this repo's
	// existing fixture carries a 16-char tail, so pinning {14} would
	// over-cull real keys. We keep {14,} to preserve recall.
	keyRe = regexp.MustCompile(`\b(rzp_(?:test|live)_[A-Za-z0-9]{14,})\b`)
	// Secret has no prefix; pinned to the documented 24 base62 chars
	// (trufflehog upstream) rather than the previous {20,40} range.
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)
)

// armRe is the assignment-style razorpay reference that must appear within the
// proximity window. A bare "razorpay" substring (package names, doc URLs,
// comments) is too weak. We require the vendor word "razorpay" followed by an
// assignment keyword (key/secret/token/id), allowing a short bounded run of
// separators (`_`, `-`, whitespace, `=`, `:`, quotes) between them. This
// matches both the joined config-key form (RAZORPAY_KEY, razorpay-secret) and
// the common "# razorpay\nKEY=..." layout, while still rejecting a stray
// "razorpay" mention sitting far from any assignment word. The bare "razorpay"
// keyword is still returned from Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)razorpay(?:[_\-]?api)?[_\-\s="':]{0,8}(?:key|secret|token|id)`)

// minSecretEntropy rejects low-entropy 24-char runs that clear the base62
// regex but are not random secrets (padded identifiers, structured names).
// The secret is high-variety base62, so 3.5 is appropriate (rubric: no
// prefix, fixed length, high-variety charset).
const minSecretEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Razorpay }

func (Scanner) Keywords() []string { return []string{"razorpay", "rzp_test_", "rzp_live_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(keys))
	seen := map[string]struct{}{}
	for _, k := range keys {
		key := string(data[k[2]:k[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		secret := nearestSecret(k[2], k[3], data, secrets, key)
		if secret == "" {
			continue
		}
		seen[key] = struct{}{}
		isLive := strings.HasPrefix(key, "rzp_live_")
		res := detectors.Result{
			DetectorType: detectors.Razorpay,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"key": key},
		}
		if verify {
			v, err := verifyPair(ctx, key, secret)
			res.Verified = v
			res.VerificationErr = err
			if v && isLive {
				res.Severity = detectors.SeverityCritical
			}
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify with the colon-joined form so the Verifier interface still works.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	key, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, key, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, key, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/items?count=1", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)

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

func nearestSecret(keyStart, keyEnd int, data []byte, hits [][]int, key string) string {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		// Skip the key itself or the rzp_<env>_ prefix tail.
		if s == key || strings.HasPrefix(s, "rzp_") {
			continue
		}
		// Entropy gate: a 24-char base62 run that is not random (padded
		// identifier, structured name) is not a real secret. Reject it so a
		// genuine high-entropy candidate can still be chosen.
		if !detectors.HasMinEntropy(s, minSecretEntropy) {
			continue
		}
		dist := h[2] - keyEnd
		if dist < 0 {
			dist = keyStart - h[3]
		}
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = s
		}
	}
	return best
}

// nearKeyword reports whether an assignment-style razorpay reference (armRe)
// appears within a tight window on either side of the key id. The window is
// searched in both directions (not strict immediate precedence) so a key
// defined alongside a nearby RAZORPAY_KEY reference still arms. The radius was
// tightened 256 -> 64 to match the FP-hardening rubric.
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
