// Package jira detects Atlassian Jira API tokens (24-char base62) near a
// "jira" assignment-style keyword.
//
// # Verify is unverified-by-design (class b)
//
// Atlassian Cloud's token-bearing endpoint, GET /rest/api/3/myself, uses HTTP
// Basic auth where the *username* is the account email and the *password* is
// the API token, addressed to the workspace host <workspace>.atlassian.net.
// The matched secret here is a bare 24-char base62 token carrying neither the
// email nor the workspace host, and neither can be derived from the token. A
// token-only probe returns 401 for *every* token, valid or revoked, so a probe
// could never legitimately yield Verified=true. Verification is therefore
// infeasible (not merely unimplemented), and we surface findings as
// Verified=false-by-design so operators can rotate without a liveness check.
//
// # Hardening
//
// The 24-char base62 shape is generic, so the bare-substring "jira" vicinity
// produced false positives on git short-SHA fragments, session/correlation
// ids, and build identifiers that merely happened to sit near the word "jira".
// We tighten with three structural gates:
//
//  1. Entropy floor — drop low-information 24-char runs (padded hashes,
//     repeated build ids) below 3.5 bits/char.
//  2. Assignment-anchored vicinity — the keyword must appear as a delimited
//     jira<...>(token|key|api|secret)? assignment within 48 bytes, not as a
//     bare substring anywhere in a 256-byte window.
//  3. Negative lookalikes — reject pure 24-hex (git/sha fragments, hex
//     digests) and reject runs lacking the mixed-case+digit profile typical of
//     Atlassian base62 tokens (all-lowercase, all-uppercase, all-digit).
package jira

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// 24 base62 characters. Same shape as `atlassian` — we differentiate by the
// "jira" assignment keyword window, not by token format.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24})\b`)

// assignmentRe requires the keyword to look like a config/env assignment:
// jira, optionally followed by word/dash chars and one of token|key|api|secret,
// then a ':' or '=' delimiter. This rejects prose mentions like "JIRA-1234".
var assignmentRe = regexp.MustCompile(`(?i)jira[\w-]*(?:token|key|api|secret)?\s*[:=]`)

// pure 24-hex == git short-blob/sha fragment or a hex digest slice — never an
// Atlassian base62 token.
var hexOnlyRe = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)

// Atlassian base62 tokens mix at least one uppercase, one lowercase, and one
// digit. The structural classes below let us reject monotone runs.
var (
	hasUpperRe = regexp.MustCompile(`[A-Z]`)
	hasLowerRe = regexp.MustCompile(`[a-z]`)
	hasDigitRe = regexp.MustCompile(`[0-9]`)
)

// minEntropy is the bits/char floor for a 24-char base62 candidate (alphabet
// ceiling ≈ 6.0). 3.5 drops padded/repeated low-information strings while
// keeping genuine tokens (which measure > 4.0).
const minEntropy = 3.5

// vicinityRadius is the byte distance within which an assignment-style "jira"
// keyword must appear, on either side of the candidate.
const vicinityRadius = 48

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jira }

func (Scanner) Keywords() []string { return []string{"jira"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		start, end := h[2], h[3]
		token := string(data[start:end])
		if _, dup := seen[token]; dup {
			continue
		}
		if !looksLikeToken(token) {
			continue
		}
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearAssignment(data, start, end) {
			continue
		}
		seen[token] = struct{}{}
		// Verified=false by design — see package doc.
		out = append(out, detectors.Result{
			DetectorType: detectors.Jira,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	return out, nil
}

// looksLikeToken rejects negative lookalikes: pure hex (git/sha fragments and
// hex digests) and monotone runs that lack the mixed-case+digit profile of an
// Atlassian base62 token.
func looksLikeToken(token string) bool {
	if hexOnlyRe.MatchString(token) {
		return false
	}
	return hasUpperRe.MatchString(token) &&
		hasLowerRe.MatchString(token) &&
		hasDigitRe.MatchString(token)
}

// nearAssignment reports whether an assignment-style "jira" keyword appears
// within vicinityRadius bytes on either side of the candidate. A bare mention
// of "jira" in surrounding prose no longer qualifies — only a delimited
// jira...[:=] assignment does.
func nearAssignment(data []byte, start, end int) bool {
	from := start - vicinityRadius
	if from < 0 {
		from = 0
	}
	to := end + vicinityRadius
	if to > len(data) {
		to = len(data)
	}
	return assignmentRe.Match(data[from:to])
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
