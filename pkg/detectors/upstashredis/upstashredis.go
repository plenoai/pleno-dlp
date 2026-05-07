// Package upstashredis detects Upstash Redis REST tokens (long base64 near
// `upstash`).
//
// Verify is intentionally not performed. Upstash REST tokens are bound to
// a per-database host in the form `<region>-<name>-<id>.upstash.io` —
// the host isn't predictable from the token alone and we frequently don't
// see it in the same chunk. Probing a guessed host would either 404 or
// hit the wrong tenant. We surface unverified-by-design at SeverityHigh
// and capture the host into ExtraData when we *do* see it next to the
// token, to help triage.
package upstashredis

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Upstash REST tokens are 50-100 base64url characters, frequently rendered
// with the `A` alphabet padding. We require co-occurrence with the
// `upstash` keyword to keep this off generic JWT/base64 hits.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{50,128})\b`)

// Optional: capture the database host so reviewers know which Upstash
// project to rotate.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.upstash\.io)\b`)

var contextKeywords = []string{"upstash", "upstash_redis", "upstash_token", "upstash_rest"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.UpstashRedis }

func (Scanner) Keywords() []string { return []string{"upstash"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	host := hostRe.FindString(lower)

	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		// The token regex catches the host portion too — exclude any
		// match that is the host string itself.
		if strings.Contains(token, ".upstash.io") {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = host
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.UpstashRedis,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
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
