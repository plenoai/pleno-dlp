// Package twitch detects Twitch OAuth client_secret values (30-char alnum
// co-occurring with `twitch` keyword) and verifies them against the
// /oauth2/validate endpoint after a client-credentials exchange.
//
// Twitch app secrets grant the issuing app's full scope (chat, channel
// API, EventSub). The 30-char alnum shape collides with many opaque
// tokens, so a co-occurring `twitch` keyword is mandatory.
//
// Verify exchanges the client_secret for an app-access token, then
// validates the token. The exchange requires a client_id which is rarely
// alongside the secret in code, so we fall back to surfacing the leak
// unverified-by-design when client_id isn't extractable. We still
// implement Verify for the case where both values land in the same chunk
// (the common shape for `.env` dumps).
package twitch

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://id.twitch.tv"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 30-char lowercase base36 (`[0-9a-z]`), no prefix. trufflehog upstream pins
// exactly this shape (`\b([0-9a-z]{30})\b`) and Twitch's own CLI validates the
// client_secret as exactly 30 chars; the docs OAuth example
// (`41vpdji4e9gif29md0ouet6fktd2`) is lowercase alphanumeric. The earlier
// mixed-case `[A-Za-z0-9]` shape was a guess — restricting to lowercase base36
// alone discards UUIDs, mixed-case build IDs, and base64 blobs that previously
// collided with this generic 30-char window.
//
// Source: trufflehog pkg/detectors/twitch/twitch.go (`[0-9a-z]{30}`);
// twitchdev/twitch-cli#4 (exactly-30 validation).
var tokenRe = regexp.MustCompile(`\b([0-9a-z]{30})\b`)

// minEntropy rejects low-information 30-char lowercase runs that clear the
// charset+length regex but lack secret-grade randomness. Base36 entropy caps
// near log2(36)=5.17 bits/char and real 30-char secrets sit ~4.5-5.0, so a
// 3.5 floor is well clear of recall risk (the documented example is ~4.1 at 28
// chars; a full 30-char secret is higher).
const minEntropy = 3.5

// armRe is the assignment-style Twitch reference required within the proximity
// window. A bare `twitch` substring (CDN/embed URLs like `player.twitch.tv`,
// doc links, `twitch.tv` channel references) is too weak a gate against a
// generic 30-char lowercase run; this is the shape a real client_secret
// assignment or config key takes. The bare `twitch` keyword is kept in
// Keywords() as the cheap prefilter.
var armRe = regexp.MustCompile(`(?i)twitch[_\-.]?(client[_\-]?)?(api[_\-]?)?(token|key|secret|client[_\-]?secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Twitch }

func (Scanner) Keywords() []string { return []string{"twitch"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Entropy gate: structured/low-information 30-char lowercase runs
		// clear the charset+length regex but are not random secrets — reject
		// them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Twitch,
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

// Verify probes /oauth2/validate by treating the candidate as an OAuth
// access token. Real client_secret values fail this check (it expects an
// access token, not a secret) — so this only verifies a positive when the
// chunk happens to contain a usable Twitch access token. Operators
// rotating an app should treat the leak as critical regardless.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/oauth2/validate", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "OAuth "+secret)

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

// nearKeyword reports whether an assignment-style Twitch reference (armRe)
// appears within a tight window on either side of the candidate. The window
// spans both directions so a secret defined alongside a nearby
// TWITCH_CLIENT_SECRET reference still arms.
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
