// Package pingidentity detects Ping Identity (PingOne) worker/client app
// secrets (UUID v4 shape). Ping uses per-region hosts (api.pingone.com,
// api.pingone.eu, api.pingone.asia, api.pingone.ca) and OAuth2
// client_credentials grants that require a client_id + client_secret PAIR;
// a lone UUID cannot authenticate, so verification is
// unverified-by-design.
//
// PingOne's own non-secret resource identifiers (environment IDs, app IDs,
// population IDs, correlation/trace/request IDs) share the exact UUID v4
// shape, so a bare keyword-vicinity gate produces unacceptable noise. The
// gate is therefore hardened: a secret-intent assignment keyword must sit
// immediately (~64 bytes) before the UUID, resource-ID lookalikes within
// the left context are excluded, the regex requires RFC4122 v4 nibbles,
// and a Shannon-entropy floor rejects sequential placeholder UUIDs.
package pingidentity

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// tokenRe matches an RFC4122 v4 UUID: version nibble fixed to 4 and the
// variant nibble constrained to [89ab]. This rejects arbitrary 32-hex
// blobs that are not real PingOne secrets.
var tokenRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\b`)

// secretKeywords are REQUIRED secret-intent assignment keywords; a bare
// "pingone"/"pingidentity" mention is intentionally NOT a gate because it
// co-occurs with non-secret PingOne resource identifiers.
var secretKeywords = []string{
	"client_secret",
	"worker_secret",
	"ping_secret",
	"pingone_secret",
	"app_secret",
}

// idLookalikes mark the UUID as a non-secret PingOne resource identifier
// when present in the immediate left context. Keys ending in "_id" are
// also rejected via a dedicated regex below.
var idLookalikes = []string{
	"environment_id",
	"env_id",
	"app_id",
	"population_id",
	"correlation",
	"trace",
	"request_id",
	"uid",
}

// leftIDKeyRe matches an assignment whose key ends in "_id" immediately to
// the left of the UUID (e.g. `environment_id: <uuid>`, `app_id=<uuid>`).
var leftIDKeyRe = regexp.MustCompile(`[a-z0-9]_id\s*[:=]\s*"?$`)

const (
	// secretRadius bounds how far before the UUID a secret-intent keyword
	// may sit. Adjacent assignment only, not anywhere in the chunk.
	secretRadius = 64
	// idRadius bounds the negative-lookalike left-context window.
	idRadius = 32
	// minEntropy drops low-entropy/sequential placeholder UUIDs such as
	// 00000000-0000-4000-8000-000000000000.
	minEntropy = 3.0
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PingIdentity }

func (Scanner) Keywords() []string { return []string{"ping"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		// Require an adjacent secret-intent assignment keyword.
		if !nearSecretKeyword(lower, h[2]) {
			continue
		}
		// Reject PingOne resource-ID lookalikes.
		if looksLikeResourceID(lower, h[2]) {
			continue
		}
		// Reject sequential/placeholder UUIDs by entropy floor over the
		// hex characters (dashes stripped).
		if !detectors.HasMinEntropy(strings.ReplaceAll(token, "-", ""), minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PingIdentity,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearSecretKeyword reports whether a required secret-intent keyword sits
// within secretRadius bytes preceding the UUID.
func nearSecretKeyword(lower string, start int) bool {
	from := start - secretRadius
	if from < 0 {
		from = 0
	}
	window := lower[from:start]
	for _, kw := range secretKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// looksLikeResourceID reports whether the immediate left context marks the
// UUID as a non-secret PingOne resource identifier.
func looksLikeResourceID(lower string, start int) bool {
	from := start - idRadius
	if from < 0 {
		from = 0
	}
	window := lower[from:start]
	for _, kw := range idLookalikes {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return leftIDKeyRe.MatchString(window)
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
