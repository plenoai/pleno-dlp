// Package onesignal detects OneSignal REST API keys near the `onesignal`
// keyword. Two documented shapes:
//   - legacy: a lowercase-hex UUID (8-4-4-4-12), matching the upstream
//     trufflehog detector which gates `onesignal` + common.UUIDPattern.
//   - v2: `os_v2_app_<base32>` — a prefix-anchored token; OneSignal's own
//     docs show a 103-char base32 body (charset a-z2-7).
//
// The legacy regex was previously a bare `[A-Za-z0-9]{48}` with a radius-256
// bare-substring gate and no entropy floor: both the wrong shape AND a heavy
// false-positive source (any 48-char alnum run anywhere near the word
// "onesignal" matched). It is now pinned to the documented UUID layout, whose
// fixed dash offsets are self-distinguishing, plus a conservative entropy
// floor; the keyword gate is replaced with an assignment-anchor arm regex
// within a tight window. The v2 shape is already prefix-anchored and unchanged.
//
// Verified via /api/v1/apps on api.onesignal.com with the key in an
// Authorization header (OneSignal accepts the raw key, not base64-encoded,
// per their docs).
//
// Sources:
//   - trufflehog pkg/detectors/onesignal (regex = PrefixRegex{"onesignal"} +
//     common.UUIDPattern; verify GET https://onesignal.com/api/v1/apps).
//   - trufflehog pkg/common/patterns.go: UUIDPattern =
//     `\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`.
//   - OneSignal API docs example key:
//     os_v2_app_<103-char a-z2-7 base32 body>.
package onesignal

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.onesignal.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// legacyRe matches the documented OneSignal legacy REST API key: a
// lowercase-hex UUID (8-4-4-4-12). This mirrors trufflehog's upstream
// detector, which gates the `onesignal` keyword against common.UUIDPattern.
var legacyRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)

// v2Re matches the OneSignal v2 token: prefix-anchored `os_v2_app_` + base32
// body (charset a-z2-7). The prefix carries the false-positive load, so no
// entropy floor is needed here.
var v2Re = regexp.MustCompile(`\b(os_v2_app_[a-z2-7]{50,200})\b`)

// armRe is the assignment-style OneSignal reference that must appear within the
// proximity window. A bare "onesignal" substring (SDK script-src URLs, doc
// links, dependency names) is too weak a gate against a generic hex UUID, which
// occurs constantly (object ids, request ids, trace ids);
// `onesignal[_-]?(rest[_-]?)?(api[_-]?)?(key|token|secret)` is the shape a real
// credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)onesignal[_\-]?(rest[_\-]?)?(api[_\-]?)?(key|token|secret)`)

// minEntropy is a conservative floor for the legacy UUID. UUIDs are
// lowercase-hex (low-variety: hex caps ~3.6 bits/char), so per the hardening
// rubric we use 3.0 — high enough to drop all-zero / repeated-nibble
// placeholders, low enough that any real random UUID clears it. The v2 token
// is prefix-anchored and not entropy-gated.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OneSignal }

func (Scanner) Keywords() []string { return []string{"onesignal", "os_v2_app_"} }

type candidate struct {
	hit  []int
	isV2 bool // prefix-anchored; skip the entropy floor
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	var cands []candidate
	for _, h := range legacyRe.FindAllSubmatchIndex(data, -1) {
		cands = append(cands, candidate{hit: h, isV2: false})
	}
	for _, h := range v2Re.FindAllSubmatchIndex(data, -1) {
		cands = append(cands, candidate{hit: h, isV2: true})
	}
	if len(cands) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(cands))
	seen := map[string]struct{}{}
	for _, c := range cands {
		h := c.hit
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// An `onesignal[_-]?...(key|token|secret)` reference within a tight
		// window is mandatory — a bare hex UUID is far too common to surface on
		// a loose substring match.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate on the legacy UUID only: drops all-zero / repeated-nibble
		// placeholder UUIDs. The v2 token is prefix-anchored and exempt.
		if !c.isV2 && !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.OneSignal,
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

// nearKeyword reports whether an `onesignal[_-]?...(key|token|secret)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby ONESIGNAL_REST_API_KEY reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/apps", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Basic "+secret)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
