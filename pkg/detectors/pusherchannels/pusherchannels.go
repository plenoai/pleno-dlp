// Package pusherchannels detects Pusher Channels app secrets — a 20-character
// lowercase-alphanumeric secret used together with an app id and key for HMAC signing
// the realtime API. Verified by signing an `auth_version=1.0` request to
// /apps/<app_id>/events would require the app id; without it, surfaced as
// unverified-by-design (HMAC scheme, write API only).
package pusherchannels

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is here for completeness; verification is unverified-by-design
// because Pusher requires app_id + key + secret + cluster, not just the
// secret. Hosts are <cluster>.pusher.com.
var apiBase = "https://api.pusher.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Pusher Channels key and secret are documented as 20-character lowercase
// alphanumeric strings (lowercase hex in practice). Source: trufflehog
// upstream pkg/detectors/pusherchannelkey (`[a-z0-9]{20}`) and the official
// auth-signatures docs, whose worked examples are lowercase-hex 20-char
// values (e.g. key 278d425bdf160c739803, secret 7ad3773142a6692b25b8).
// https://pusher.com/docs/channels/library_auth_reference/auth-signatures/
// The charset is therefore [a-z0-9], NOT [A-Za-z0-9]; uppercase runs are not
// valid Pusher credentials and only widened the false-positive surface.
var tokenRe = regexp.MustCompile(`\b([a-z0-9]{20})\b`)

// armRe is the assignment-style Pusher reference that must appear within the
// proximity window. A bare "pusher" substring (CDN script-src URLs, dependency
// names, comments) is too weak; "pusher_secret" / "pusher-app-key" / etc. is
// the shape a real credential assignment or config key takes. Kept tight to
// the documented secret/key/token roles.
var armRe = regexp.MustCompile(`(?i)pusher[_\-]?(app[_\-]?)?(secret|key|token)`)

// minEntropy rejects low-variety 20-char lowercase-alnum runs that clear the
// regex but are not random credentials. Pusher secrets are lowercase hex, so
// entropy caps near log2(16)=4.0 and real examples sit at ~3.1-3.7 (measured:
// 8897fad3dbbb3ac533a9=3.15, 7ad3773142a6692b25b8=3.45). A 3.5 floor would
// over-cull genuine secrets; 3.0 is the recall-safe floor for this charset.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PusherChannels }

func (Scanner) Keywords() []string { return []string{"pusher"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: low-variety 20-char lowercase-alnum runs (padded
		// identifiers, repeated chars) are rejected even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.PusherChannels,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Unverified by design: HMAC signing scheme requires app_id + cluster
		// not in the chunk.
		_ = verify
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether a pusher credential reference (armRe) appears
// within a tight window on either side of the token. The window spans both
// directions (not strict immediate precedence) so a secret defined alongside a
// nearby PUSHER_SECRET reference still arms. Radius tightened 256->64 to cut
// the false-positive surface for these generic 20-char runs.
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

// Verify probes the user-overridable apiBase. Real verification requires
// HMAC signing with app_id + key + cluster; this stub is here for the
// Verifier-interface contract and for tests.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/apps/_/info?auth_key="+secret, nil)
	if err != nil {
		return false, err
	}
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
