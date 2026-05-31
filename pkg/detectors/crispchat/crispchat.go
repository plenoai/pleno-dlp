// Package crispchat detects Crisp Chat (crisp.chat) plugin tokens — long
// lowercase-hex plugin keys near a `crisp` keyword. Crisp uses an
// Identifier+Key pair for plugin authentication; we surface the secret-key as
// Raw because the Identifier is a UUID and not by itself sensitive. The Crisp
// API authenticates exclusively via HTTP Basic with `Identifier:Key`
// (username:password) against api.crisp.chat with the `X-Crisp-Tier: plugin`
// header — the Key alone is not a credential any endpoint accepts, so this
// detector is unverified-by-design (an Identifier-aware variant would have to
// read both halves from the chunk via RawV2).
//
// Hardening: the embed `<script src="https://client.crisp.chat/l.js">` tag is
// typically surrounded by long tokens that are NOT secrets — SRI integrity
// hashes (sha256/384/512 base64), webpack/asset content hashes, and CDN URLs.
// To keep those out we (1) constrain the charset to lowercase-hex of the
// documented length, (2) require an assignment-style keyword within a tight
// window before the token rather than mere co-occurrence of "crisp" anywhere
// on the page, (3) gate on Shannon entropy, and (4) exclude SRI/CDN contexts.
package crispchat

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Crisp plugin keys are documented as fixed-length lowercase-hex tokens
// (64 chars in practice). Narrowing to lowercase-hex of >=40 excludes the
// mixed-case base64 used by SRI integrity attributes and webpack chunk names.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{40,128})\b`)

// minEntropy rejects low-entropy runs (repeated chars, dictionary-ish or
// structured-but-non-random hex) that clear the length floor but are not keys.
const minEntropy = 3.5

// proximityRadius is the number of bytes BEFORE the token in which an
// assignment-style Crisp reference must appear. Tight enough that a
// `crisp.chat` script-src URL elsewhere on the page no longer arms a token.
const proximityRadius = 48

// armKeywords are the assignment-style references that must precede a token
// within proximityRadius bytes. These are the shapes a real Crisp key
// assignment takes in config/env/source.
var armKeywords = []string{
	"crisp_token",
	"crisp_api_key",
	"crisp_key",
	"crisp_api",
	"crisp-key",
	"crisp-token",
	"crispkey",
	"crisptoken",
	"crisp_plugin",
}

// sriMarkers indicate the token lives inside a Subresource Integrity attribute
// or a CDN asset URL — the dominant false-positive source near the embed.
var sriMarkers = []string{
	"integrity=",
	"sha256-",
	"sha384-",
	"sha512-",
	"client.crisp.chat",
	"crisp.chat/l.js",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CrispChat }

func (Scanner) Keywords() []string { return []string{"crisp"} }

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
		// Entropy gate: structured/repeated hex (e.g. a content digest that
		// happens to be lowercase-hex) without real randomness is rejected.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// Require an assignment-style Crisp reference in a tight window before
		// the token, not a stray "crisp" substring anywhere in the chunk.
		if !armedByKeyword(lower, h[2]) {
			continue
		}
		// Exclude SRI integrity / CDN-asset contexts around the token.
		if inSRIContext(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.CrispChat,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// armedByKeyword reports whether an assignment-style Crisp reference appears in
// the proximityRadius bytes immediately preceding the token.
func armedByKeyword(lower string, start int) bool {
	from := start - proximityRadius
	if from < 0 {
		from = 0
	}
	window := lower[from:start]
	for _, kw := range armKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// inSRIContext reports whether SRI/CDN markers surround the token, indicating
// the match is an integrity hash or asset URL rather than a plugin key.
func inSRIContext(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, m := range sriMarkers {
		if strings.Contains(window, m) {
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
