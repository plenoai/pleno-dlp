// Package tektonhub detects Tekton Hub API tokens captured from an explicit
// token assignment (e.g. `tekton_hub_token = <value>`).
//
// Unverified-by-design rationale: Tekton Hub auth tokens are JWTs
// (header.payload.signature) sent verbatim in the Authorization header, and
// the hub is community-hosted (api.hub.tekton.dev) or arbitrarily self-hosted
// with no host derivable from the token or chunk. The shape this detector can
// realistically extract from config is a plain base62 blob (the `[A-Za-z0-9]`
// class plus a word/quote boundary cannot span the mandatory JWT dots), which
// is NOT the credential any Tekton Hub endpoint accepts. A live probe against
// GET /v1/auth/me would therefore reject every real match (and could falsely
// verify against an unrelated host that 200s a bearer), so verification is
// infeasible — this detector stays unverified-by-design.
//
// To control the otherwise severe false-positive rate inside Tekton YAML
// (image digests, git SHAs, resource UIDs, base64 chunks all sit near the word
// `tekton`), the match is anchored to a token-specific assignment keyword
// within ~40 bytes, gated on Shannon entropy, and excludes hex-only /
// 64-char-hex (container image digest) lookalikes.
package tektonhub

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// tokenRe anchors the capture to a token-specific assignment keyword in a
// quoted/assignment context, so generic Tekton manifest blobs near the word
// `tekton` no longer qualify. The keyword and the value must sit within the
// same assignment expression (the `\s{0,4}` between separator characters keeps
// them within ~40 bytes of each other).
var tokenRe = regexp.MustCompile(
	`(?i)(?:tekton_hub_token|tekton_hub_api_token|tekton_token|hub_token|authorization)["']?\s{0,4}[:=]\s{0,4}["']?(?:bearer\s{0,4})?([A-Za-z0-9]{40,80})\b`,
)

// hexOnlyRe rejects pure-hex strings (image-digest / SHA shaped) which are the
// dominant false positive in Tekton YAML.
var hexOnlyRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TektonHub }

func (Scanner) Keywords() []string { return []string{"tekton"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h[1])
		if _, dup := seen[token]; dup {
			continue
		}
		if !plausibleToken(token) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.TektonHub,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// plausibleToken applies the negative-lookalike and entropy gates.
func plausibleToken(token string) bool {
	// Reject pure-hex (image digests, SHAs, hex digests) — and 64-char hex in
	// particular, the container image digest shape that dominates Tekton YAML.
	if hexOnlyRe.MatchString(token) {
		return false
	}
	// Reject low-entropy lookalikes (repeated/structured names).
	if !detectors.HasMinEntropy(token, minEntropy) {
		return false
	}
	return true
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
