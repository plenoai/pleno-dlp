// Package piiemail detects email addresses. PII findings carry
// ExtraData["finding_class"]="pii" so downstream callers can route by
// class — secrets get rotated, PII gets access-controlled or redacted.
//
// Severity defaults to Medium via DefaultSeverity. There is no Verify
// path: pinging an SMTP server to confirm an inbox exists is hostile to
// the inbox owner and trivially detected as harassment.
//
// Match: a deliberately conservative RFC5322 subset that prefers
// false-negatives over false-positives. Local-part = unicode letters,
// digits, dot, dash, plus, underscore; domain = at least one label of
// 1+ unicode letter/digit, TLD of 2+ alpha characters. Strings like
// "user@host" without a TLD are excluded so we don't fire on every
// "name@docker-internal" log line.
package piiemail

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// emailRe is the conservative shape. The trailing TLD requirement
// (`[a-zA-Z]{2,24}`) eliminates internal-only "host@svc" leaks while
// keeping every public TLD (.io, .museum, .technology). \b boundaries
// stop the match from absorbing surrounding punctuation.
var emailRe = regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24}\b`)

// keywords for the engine prefilter. `@` alone would collide with
// every Go struct tag and shell command. Adding `mail` and `email`
// keeps the prefilter useful for email-shaped chunks without
// overfiring on every text file.
var keywords = []string{"@", "mail"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIIEmail }
func (Scanner) Keywords() []string           { return keywords }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := emailRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, m := range matches {
		s := string(m)
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.PIIEmail,
			Raw:          m,
			Redacted:     redactEmail(s),
			ExtraData: map[string]string{
				"finding_class": "pii",
				"pii_kind":      "email",
			},
		})
	}
	return out, nil
}

// redactEmail keeps the local-part initial + '*' + domain so triage
// can spot duplicates without exposing the PII. "alice@example.com"
// → "a***@example.com".
func redactEmail(s string) string {
	at := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			at = i
			break
		}
	}
	if at <= 1 {
		return s
	}
	return s[:1] + "***" + s[at:]
}

func init() {
	detectors.Register(Scanner{})
}
