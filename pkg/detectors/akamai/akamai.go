// Package akamai detects Akamai EdgeGrid client_secret strings (32+ char
// base64) gated on client_secret / edgegrid assignment context. Akamai's
// EdgeGrid auth is an HMAC scheme: signing any request needs FOUR
// co-located components — a per-account host (*.akamaiapis.net), a
// client_token, a client_secret, and an access_token — combined into an
// HMAC-SHA256 over a canonicalized request with timestamp+nonce. This
// detector captures only the client_secret, so there is no signable
// request and no target host to verify against. It is therefore
// unverified-by-design (class b).
//
// Because the bare token shape `[A-Za-z0-9+/=_\-]{32,}` is otherwise
// indistinguishable from CDN path tokens, ETags, git SHAs, and Akamai
// cookie values (ak_bmsc, bm_sv, _abck, …) that pervade Akamai-served
// content, the matcher is hardened beyond a plain `akamai` keyword gate:
//
//  1. The structured .edgerc form `client_secret = <value>` is accepted
//     directly with high confidence.
//  2. The windowed fallback requires a client_secret/edgegrid assignment
//     anchor inside a tight ~128-byte window AND a Shannon-entropy floor
//     of 4.0 bits/char (real EdgeGrid secrets are high-entropy random
//     base64; structured/repeated CDN tokens fall below this).
//  3. Negative exclusions reject pure-hex values (SHAs/ETags/hashes),
//     values living on a URL or Set-Cookie/Cookie line, and values
//     adjacent to known Akamai cookie names.
package akamai

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// minEntropy is the Shannon bits/char floor for windowed-fallback
// candidates. Real EdgeGrid client_secrets are random base64 (alphabet
// ~64, ceiling ≈ 6.0); structured CDN path tokens and repeated cookie
// values sit well below 4.0.
const minEntropy = 4.0

// contextRadius bounds how far an assignment anchor may sit from the
// candidate in the windowed fallback. EdgeGrid secrets live in .edgerc
// under a client_secret key, so the anchor is right next to the value;
// a tight window starves the ubiquitous `akamai` mentions in CDN content.
const contextRadius = 128

// edgercRe captures the high-confidence structured form
// `client_secret = <value>` as found in an .edgerc credentials file.
var edgercRe = regexp.MustCompile(`(?i)client_secret\s*[=:]\s*([A-Za-z0-9+/=_\-]{32,80})`)

// tokenRe is the loose fallback candidate shape. `=` is only allowed as
// trailing base64 padding (not interior) so the match does not swallow a
// `key=value` assignment prefix like `client_secret=`.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9+/_\-]{32,80}={0,2})`)

// hexRe matches pure-hex values (git SHAs, ETags, content hashes) which
// are not EdgeGrid secrets even when they meet the length bound.
var hexRe = regexp.MustCompile(`^[a-fA-F0-9]+$`)

// anchorKeywords are the assignment-context anchors required for the
// windowed fallback. The bare word `akamai` is intentionally NOT here:
// it is the engine prefilter keyword but is too common in CDN content to
// gate on alone.
var anchorKeywords = []string{"client_secret", "edgegrid", "akamai_client_secret", "akamai_secret"}

// akamaiCookieNames are Akamai-set cookie names; a candidate adjacent to
// one is a cookie value, not a credential.
var akamaiCookieNames = []string{"ak_bmsc", "bm_sv", "bm_mi", "_abck", "akamai-"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Akamai }

func (Scanner) Keywords() []string { return []string{"akamai", "client_secret", "edgegrid"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	lower := strings.ToLower(string(data))
	seen := map[string]struct{}{}
	out := make([]detectors.Result, 0)

	emit := func(token string) {
		if _, dup := seen[token]; dup {
			return
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Akamai,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}

	// Pass 1: high-confidence structured .edgerc form. Still subject to the
	// negative exclusions (a hex value assigned to client_secret is junk).
	for _, h := range edgercRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		if rejectToken(token) {
			continue
		}
		emit(token)
	}

	// Pass 2: windowed fallback. Requires an assignment anchor inside a
	// tight window AND the entropy floor.
	for _, h := range tokenRe.FindAllSubmatchIndex(data, -1) {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if rejectToken(token) {
			continue
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearAnchor(lower, h[2], h[3]) {
			continue
		}
		if onURLOrCookieLine(data, h[2]) {
			continue
		}
		emit(token)
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// rejectToken applies length and lookalike exclusions shared by both passes.
func rejectToken(token string) bool {
	if len(token) < 32 || len(token) > 80 {
		return true
	}
	// Pure hex => git SHA / ETag / content hash, not an EdgeGrid secret.
	if hexRe.MatchString(token) {
		return true
	}
	return false
}

// nearAnchor reports whether an assignment-context anchor sits within
// contextRadius bytes of the candidate, and that the candidate is not
// adjacent to a known Akamai cookie name (which would make it a cookie
// value rather than a credential).
func nearAnchor(lower string, start, end int) bool {
	from := start - contextRadius
	if from < 0 {
		from = 0
	}
	to := end + contextRadius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, name := range akamaiCookieNames {
		if strings.Contains(window, name) {
			return false
		}
	}
	for _, kw := range anchorKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

// onURLOrCookieLine reports whether the line containing the candidate is a
// URL or a Set-Cookie/Cookie header — both common sources of long base64
// path/value tokens in Akamai-served content.
func onURLOrCookieLine(data []byte, pos int) bool {
	lineStart := pos
	for lineStart > 0 && data[lineStart-1] != '\n' {
		lineStart--
	}
	lineEnd := pos
	for lineEnd < len(data) && data[lineEnd] != '\n' {
		lineEnd++
	}
	line := strings.ToLower(string(data[lineStart:lineEnd]))
	if strings.Contains(line, "http://") || strings.Contains(line, "https://") || strings.Contains(line, "//") {
		return true
	}
	if strings.Contains(line, "set-cookie") || strings.Contains(line, "cookie:") {
		return true
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
