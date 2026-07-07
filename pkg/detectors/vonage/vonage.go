// Package vonage detects Vonage (Nexmo) API key + API secret pairs.
//
// FP-hardening (paired-credential rubric). The original gate was a bare
// `[A-Za-z0-9]{8}` key + `[A-Za-z0-9]{16}` secret with a radius-256
// strings.Contains("vonage"/"nexmo") window and no entropy floor — random
// alnum runs collide trivially, so the gate leaked.
//
// Authoritative format: the Vonage API *secret* is documented as 8-25
// characters and MUST contain at least one lowercase letter, one uppercase
// letter, and one digit (Vonage support, "How do I change my API secret"):
// https://api.support.vonage.com/hc/en-us/articles/360016547932 . We pin the
// secret to that documented length range, enforce the documented
// upper+lower+digit composition, and add HasMinEntropy(secret, 3.5) — a
// mixed-case 8-25 alnum run with full composition is high-variety, so 3.5 is
// the right floor. The composition rule alone already rejects the common FP
// shapes (all-lowercase ids, hex digests, UPPER_SNAKE constants).
//
// The API *key* length/charset is NOT authoritatively documented (dashboard
// examples are short alnum but no spec pins a length), so per the
// inconclusive-fallback rule we do NOT change the key regex — it is the
// assignment anchor for the pair, not the primary entropy carrier, and the
// arm-regex keyword gate plus the secret's hardened format carry the FP load.
//
// The keyword gate is tightened from a radius-256 bare-substring scan to an
// assignment-style arm regex within a radius-64 window; the bare keywords
// stay in Keywords() as the engine prefilter.
//
// Vonage credentials authorize SMS sends and voice calls, so verified hits
// surface SeverityCritical via engine default.
//
// Verification calls GET /account/get-balance on rest.nexmo.com with HTTP
// Basic (key:secret). This is the documented Account API endpoint that the
// api_key/api_secret pair authenticates; it returns 200 with the account
// balance on valid credentials and 401 on bad ones. The earlier /v0.1/users
// target was wrong: that path belongs to the Application/Conversation API,
// which expects a JWT (application_id + private key), so Basic key:secret was
// rejected even for valid account credentials (false Verified=false).
package vonage

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://rest.nexmo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Key: 8-char alnum. No authoritative length spec exists, so this is left
	// unchanged from the original — it serves as the assignment anchor for the
	// pair, not the entropy carrier.
	keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{8})\b`)
	// Secret: documented 8-25 char mixed-case alphanumeric. Composition
	// (upper+lower+digit) and entropy are enforced separately in FromData.
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{8,25})\b`)
)

// armRe is the assignment-style Vonage/Nexmo reference that must appear within
// the proximity window. A bare "vonage"/"nexmo" substring (npm deps, comments,
// URLs) is too weak; "vonage_api_secret", "nexmo-api-key", "vonageApiToken"
// etc. is the shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)(vonage|nexmo)[_\- ]?(api[_\- ]?)?(key|secret|token)`)

// minSecretEntropy rejects low-entropy 8-25 char runs that clear the regex and
// composition check but are not random secrets. Documented secrets are
// mixed-case alnum, so 3.5 is appropriate (the rubric's no-prefix /
// fixed-length / high-variety case).
const minSecretEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vonage }

func (Scanner) Keywords() []string { return []string{"vonage", "nexmo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keys) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secrets) == 0 {
		return nil, nil
	}
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
		secret, ok := nearestSecret(k[2], data, secrets, key)
		if !ok {
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Vonage,
			Raw:          []byte(key),
			RawV2:        []byte(key + ":" + secret),
			Redacted:     redact(key),
			ExtraData:    map[string]string{"api_key": key},
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

// The paired credential is packed as "key:secret" (matching RawV2 and the
// jumio/qualys paired-detector convention) so the single-string Verifier
// interface applies to a key+secret pair.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/account/get-balance", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Accept", "application/json")

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// ClassifyVerifyHTTP normalises the response so an ambiguous reply (500,
	// 429, transport failure) surfaces as a transient error rather than a
	// false "not valid" verdict. 200 → valid; 401/403 → explicit rejection.
	return detectors.ClassifyVerifyHTTP(resp, doErr, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
}

// nearestSecret returns the closest candidate to the key that satisfies the
// documented Vonage secret format: 8-25 mixed-case alnum (the regex), the
// upper+lower+digit composition rule, and the entropy floor. Filtering the
// candidates here (rather than only checking the single nearest run) preserves
// recall — a valid secret near the key is still found even when a closer alnum
// run fails the format checks.
func nearestSecret(keyStart int, data []byte, hits [][]int, keyValue string) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		candidate := string(data[h[2]:h[3]])
		if candidate == keyValue {
			continue
		}
		// Documented composition: lowercase + uppercase + digit. Rejects
		// all-lowercase ids, hex digests, and UPPER_SNAKE constants.
		if !hasRequiredComposition(candidate) {
			continue
		}
		// Entropy floor for the high-variety mixed-case secret shape.
		if !detectors.HasMinEntropy(candidate, minSecretEntropy) {
			continue
		}
		dist := abs(h[2] - keyStart)
		if dist < bestDist {
			bestDist = dist
			best = candidate
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// hasRequiredComposition enforces the documented Vonage API-secret rule:
// at least one lowercase letter, one uppercase letter, and one digit.
func hasRequiredComposition(s string) bool {
	var hasLower, hasUpper, hasDigit bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		}
	}
	return hasLower && hasUpper && hasDigit
}

// nearKeyword reports whether an assignment-style Vonage/Nexmo credential
// reference (armRe) appears within a tight radius-64 window on either side of
// the key candidate. The window spans both directions so a key defined
// alongside a nearby VONAGE_API_SECRET reference still arms.
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
