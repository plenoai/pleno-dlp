// Package keycloak detects Keycloak client_id + client_secret pairs near
// the `keycloak` keyword. Verified via /realms/<realm>/protocol/openid-connect/token
// on the per-deployment host. Unverified-by-default; the host + realm aren't
// in the chunk so verify only fires when an apiBase override is supplied.
//
// Credential format (authoritative): Keycloak generates a client secret via
// SecretGenerator.randomString(), with ALPHANUM=[A-Za-z0-9] and a length that
// matches the client's signature-algorithm key size — SECRET_LENGTH_256_BITS=32
// (the default, HS256), SECRET_LENGTH_384_BITS=48 (HS384), and
// SECRET_LENGTH_512_BITS=64 (HS512). See SecretGenerator.java (keycloak/keycloak,
// common/.../util/SecretGenerator.java). Because there is no prefix to anchor on,
// the secret half is pinned to those three documented lengths (32/48/64) with an
// entropy floor, and the keyword gate is an assignment-style arm regex within a
// tight window. Pinning ONLY 32 would silently drop the 48- and 64-char HS384/HS512
// secrets, so all three documented lengths are accepted. The client_id is an
// admin-chosen free-form string with no documented format, so it is NOT
// length-pinned — it is matched as a generic identifier and only the secret
// half carries the strict shape. Example secret value: <32-CHAR-SECRET>.
package keycloak

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

// secretRe matches a Keycloak client secret: a [A-Za-z0-9] run of one of the
// three documented SecretGenerator lengths — 32 (SECRET_LENGTH_256_BITS, the
// default), 48 (384-bit, HS384), or 64 (512-bit, HS512). The \b anchors mean a
// 48- or 64-char run is matched by the corresponding alternative rather than
// truncated to 32. No prefix exists, so length + entropy + the arm-regex keyword
// gate carry the false-positive load.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{64}|[A-Za-z0-9]{48}|[A-Za-z0-9]{32})\b`)

// idRe matches the admin-chosen client_id. This has no documented format
// (operators pick arbitrary identifiers like "my-app" or "backend-service"),
// so it is intentionally NOT length-pinned to the secret's 32 — pinning a
// free-form field would destroy recall. We accept a permissive identifier
// shape and rely on the keyword gate + secret-half rigor.
var idRe = regexp.MustCompile(`\b([A-Za-z0-9][A-Za-z0-9._\-]{2,127})\b`)

// armRe is the assignment-style Keycloak reference that must appear within the
// proximity window. A bare "keycloak" substring (script-src URLs, doc links,
// the realm host) is too weak a gate against a generic 32-char alphanumeric
// run; `keycloak[_-]?(client[_-]?)?(secret|id|key|token)` is the shape a real
// credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)keycloak[_\-]?(client[_\-]?)?(secret|id|key|token)`)

// minEntropy rejects low-entropy 32-char runs that clear the alnum regex but
// are not random secrets (e.g. padded placeholders, repeated characters,
// structured identifiers). The 62-char ALPHANUM set supports a 3.5 floor
// without over-culling real 32-char secrets.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.KeyCloak }

// Keywords must include "keycloak" — it is the engine prefilter. Without it
// the engine would evaluate the regexes against every chunk.
func (Scanner) Keywords() []string { return []string{"keycloak"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	// Find the armed secret: a 32-char [A-Za-z0-9] run, near a keycloak
	// assignment reference, that clears the entropy floor.
	var secret string
	var secretStart, secretEnd int
	for _, h := range secretHits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		secret = v
		secretStart, secretEnd = h[2], h[3]
		break
	}
	if secret == "" {
		return nil, nil
	}

	// Find a client_id: a permissive identifier near the keyword, distinct
	// from the secret. Falls back to "" — the pair is best-effort; the secret
	// is the load-bearing half.
	var id string
	for _, h := range idRe.FindAllSubmatchIndex(data, -1) {
		// Skip the exact span of the secret match.
		if h[2] == secretStart && h[3] == secretEnd {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == secret {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		id = v
		break
	}

	raw := id
	if raw == "" {
		raw = secret
	}
	res := detectors.Result{
		DetectorType: detectors.KeyCloak,
		Raw:          []byte(raw),
		RawV2:        []byte(secret),
		Redacted:     redact(raw),
	}
	if verify && apiBase != "" && id != "" {
		v, err := s.Verify(ctx, id+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a keycloak assignment-style reference appears
// within a tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a credential defined
// alongside a nearby KEYCLOAK_CLIENT_SECRET reference still arms.
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
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&client_id=" + id + "&client_secret=" + sec)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/protocol/openid-connect/token", body)
	if err != nil {
		return false, err
	}
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
