// Package datadogapp detects standalone Datadog Application keys (40 hex
// chars) anchored to a `DD-APPLICATION-KEY` / `DD_APP_KEY` assignment or
// header form.
//
// The existing `pkg/detectors/datadog` package surfaces 32-hex API keys and
// pairs them with an Application key when both are present in the same
// chunk. datadogapp is the complement: it surfaces lone 40-hex Application
// keys that show up without a sibling API key — for example in CI configs
// where the API key is supplied via a secrets manager and only the App key
// is checked into source.
//
// Verify is INFEASIBLE for a lone Application key and is therefore not
// implemented (unverified-by-design, verify-coverage class=b). Datadog's
// only key-validation endpoint, GET /api/v1/validate, authenticates the
// *API* key: it requires the DD-API-KEY header (see sibling
// pkg/detectors/datadog/datadog.go, which sets both DD-API-KEY and
// DD-APPLICATION-KEY for that call). Every Datadog endpoint that consumes an
// Application key also requires the API key. With only the App key in scope
// — which is exactly what datadogapp surfaces, since FromData skips any App
// key with a 32-hex API key nearby — there is no endpoint that authenticates
// the App key alone. Any endpoint we picked would either reject everything
// (useless) or validate the unrelated API-key dimension and risk a false
// Verified=true. So we surface the leak unverified and let
// pkg/detectors/datadog own the paired, verifiable path.
//
// Because a 40-hex token is exactly the SHA-1 / git-commit / action-pin
// shape, the match is hardened against that noise: it must follow a Datadog
// app-key key name and separator within a tight window, must clear a hex
// entropy floor, and is excluded when it sits in a SHA-1 / commit / checksum
// context.
package datadogapp

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Anchored form: a Datadog app-key key name, an optional surrounding quote /
// backtick, a `:` / `=` separator (or whitespace), optional opening quote,
// then the 40-hex token. Capturing group 1 is the token.
//
// This replaces the previous free-floating `\b[a-fA-F0-9]{40}\b` + "keyword
// anywhere in a 256-byte window" approach, which surfaced any SHA-1 that
// happened to sit near a DD_APP_KEY doc comment.
var anchoredRe = regexp.MustCompile(
	`(?i)(?:dd[-_]?application[-_]?key|dd[-_]?app[-_]?key|datadog[-_]?app(?:lication)?[-_]?key)["` + "`" + `']?\s*[:=]?\s*["` + "`" + `']?\s*([a-fA-F0-9]{40})\b`,
)

// 32-hex API keys nearby — used to skip the App key when the existing
// datadog detector will already surface the pair.
var apiRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)

// Tokens in a SHA-1 / commit / checksum context are excluded even when a
// Datadog keyword is present, because git commit SHAs and action-pin SHAs
// share the 40-hex shape. We look at the bytes immediately before the token.
var shaContextRe = regexp.MustCompile(`(?i)(sha1|sha-1|sha\b|commit|checksum|revision|digest|@)[\s:="'` + "`" + `]*$`)

// minHexEntropy: floor over the 16-symbol hex alphabet (ceiling ≈ 4.0
// bits/char). 3.0 drops all-zero / repeated-nibble placeholders and
// templated fillers while keeping any real 40-hex secret.
const minHexEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DatadogAppKey }

// The keyword gate is mandatory — 40 hex is sha1's exact shape and would
// otherwise fire on every git commit.
func (Scanner) Keywords() []string {
	return []string{"DD-APPLICATION-KEY", "DD_APPLICATION_KEY", "DD_APP_KEY"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := anchoredRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	apis := apiRe.FindAllSubmatchIndex(data, -1)

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		// h[0]:h[1] is the whole anchored match; h[2]:h[3] is the token.
		tokenStart, tokenEnd := h[2], h[3]
		token := string(data[tokenStart:tokenEnd])
		if _, dup := seen[token]; dup {
			continue
		}
		// SHA-1 / commit / checksum context exclusion: inspect the bytes
		// immediately preceding the token. A `... commit da39a3ee...` style
		// line must not be surfaced even though it sits inside the anchored
		// match window.
		if inSHAContext(data, tokenStart) {
			continue
		}
		// Entropy floor: reject all-zero, repeated-nibble, and templated
		// placeholders that pass the hex shape but carry no information.
		if !detectors.HasMinEntropy(token, minHexEntropy) {
			continue
		}
		// If a 32-hex API key sits within a tight window, the existing
		// `datadog` detector already surfaces the pair; skip to avoid a
		// duplicate finding from a different DetectorType.
		if hasNearbyAPIKey(tokenStart, apis) {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.DatadogAppKey,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// shaLookback is the tight window (in bytes) used for the SHA-1 / commit
// context exclusion. Shrunk from the old 256-byte keyword window to 40 so an
// unrelated SHA on a different config line no longer drives the decision; the
// keyword→token proximity itself is now enforced by anchoredRe, not a window.
const shaLookback = 40

// apiDedupRadius is the window for delegating paired key+secret findings to
// the `datadog` detector. This is a cross-detector de-duplication concern,
// not a noise concern, so it stays wide (256) — a `DD_API_KEY=` line followed
// by a `DD_APPLICATION_KEY=` line on the next line is a pair datadog owns even
// though the two tokens are >40 bytes apart.
const apiDedupRadius = 256

func hasNearbyAPIKey(start int, apis [][]int) bool {
	for _, a := range apis {
		if abs(a[2]-start) <= apiDedupRadius {
			return true
		}
	}
	return false
}

// inSHAContext reports whether the bytes immediately before tokenStart match
// a SHA-1 / commit / checksum lead-in. It scans a short lookback window so
// the regex anchor (`$`) lands right before the token.
func inSHAContext(data []byte, tokenStart int) bool {
	from := tokenStart - shaLookback
	if from < 0 {
		from = 0
	}
	return shaContextRe.Match(data[from:tokenStart])
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
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
