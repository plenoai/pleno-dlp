// Package livekit detects LiveKit realtime audio/video API key + secret
// pairs near the `livekit` keyword. Unverified by default — LiveKit
// servers are typically self-hosted or per-project (`<project>.livekit.cloud`),
// no canonical host. Verification fires only when an apiBase override is
// supplied.
package livekit

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// API key shape is authoritative: livekit/protocol generates it as
// `guid.New(APIKeyPrefix)` = the literal prefix "API" + exactly Size=12
// chars drawn from the shortuuid base57 alphabet (a subset of [A-Za-z0-9]).
// So an API key is exactly 15 chars, "API" + 12. The "API" prefix is a
// strong anchor; we pin the documented post-prefix length rather than the
// old loose {10,16} range.
// Source: github.com/livekit/protocol utils/guid/id.go (APIKeyPrefix="API",
// Size=12) and livekit/livekit cmd/server/commands.go (generateKeys:
// apiKey := guid.New(utils.APIKeyPrefix)).
var keyRe = regexp.MustCompile(`\b(API[A-Za-z0-9]{12})\b`)

// API secret is `utils.RandomSecret()` = base62 of 32 random bytes. base62 of a
// 32-byte buffer is NOT a fixed 43 chars: empirically (jxskiss/base62
// EncodeToString over 2M samples) the length is 43 (~50%), 44 (~50%), or 45
// (~0.1%) — pinning exactly {43} silently drops ~half of all real secrets. The
// old bare {40,48} alnum run with no entropy floor was the dominant
// false-positive surface (commit SHAs, base64 blobs, k8s names all clear it);
// we pin the documented 43-45 range and gate on entropy.
// Source: github.com/livekit/protocol utils/secret.go (RandomSecret: 32-byte
// crypto/rand buffer, base62.EncodeToString) + server >=32-char minimum
// (livekit/livekit issue #2582).
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{43,45})\b`)

// minSecretEntropy rejects 43-45-char alnum runs that clear secretRe but are
// not random 256-bit secrets (structured identifiers, padded names). 43+ random
// base62 chars sit well above 3.5; this floor only culls non-random runs and is
// the load-bearing false-positive gate now that the length range is wider. Per
// docs/detector-key-formats.md (no-prefix, fixed length, high-variety charset
// -> pin length + HasMinEntropy 3.5).
const minSecretEntropy = 3.5

// armRe is the assignment-style LiveKit reference that must appear within the
// proximity window. A bare "livekit" substring (script URLs, package names,
// docs) is too weak a gate for a fixed-length alnum secret; the shape a real
// credential assignment / config key takes is `livekit[_-]?(api[_-]?)(key|
// secret|token)`.
var armRe = regexp.MustCompile(`(?i)livekit[_\-]?(api[_\-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LiveKit }

func (Scanner) Keywords() []string { return []string{"livekit"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	secretHits := secretRe.FindAllSubmatch(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, h := range keyHits {
		key := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		for _, sh := range secretHits {
			secret := string(sh[1])
			if secret == key {
				continue
			}
			// Entropy gate: a fixed-length-43 alnum run that is not a random
			// 256-bit secret (structured id, padded name) is rejected.
			if !detectors.HasMinEntropy(secret, minSecretEntropy) {
				continue
			}
			pair := key + ":" + secret
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.LiveKit,
				Raw:          []byte(key),
				RawV2:        []byte(pair),
				Redacted:     redact(key),
			}
			if verify && apiBase != "" {
				v, err := s.verifyPair(ctx, key, secret)
				res.Verified = v
				res.VerificationErr = err
			}
			out = append(out, res)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether a `livekit[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the API key
// candidate. The window spans both directions (not strict precedence) so a
// key/secret pair defined alongside a nearby LIVEKIT_API_KEY reference still
// arms. The old gate was a bare strings.Contains("livekit") over radius 256 —
// far too loose for a generic alnum secret. Per docs/detector-key-formats.md:
// replace bare Contains over radius 256 with an arm regex within radius 64.
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, key, _ string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/twirp/livekit.RoomService/ListRooms", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
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
