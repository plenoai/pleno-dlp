// Package esmtprc detects the `password` line of an `.esmtprc` /
// `~/.esmtprc` config (esmtp(1), the lightweight SMTP relay client, and
// its msmtp/ssmtp-family lookalikes): a bare `key value` grammar, one
// directive per line, where the value is optionally double-quoted
// (`password "hunter2"` or `password hunter2`).
//
// Verify is deliberately not implemented (class b): the credential
// authenticates against the `hostname` directive elsewhere in the same
// file, an arbitrary user-configured SMTP relay, not a fixed provider
// endpoint.
package esmtprc

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// passwordLineRe matches an esmtprc `password` directive: the keyword,
// then either a double-quoted value or a bare whitespace-delimited
// token, alone on its line.
var passwordLineRe = regexp.MustCompile(
	`(?im)^[ \t]*password[ \t]+(?:"([^"\r\n]*)"|(\S+))[ \t]*$`,
)

var placeholders = map[string]struct{}{
	"password":    {},
	"changeme":    {},
	"change_me":   {},
	"example":     {},
	"placeholder": {},
	"secret":      {},
	"test":        {},
	"testing":     {},
	"dummy":       {},
	"sample":      {},
	"none":        {},
	"null":        {},
	"x":           {},
	"xxx":         {},
	"":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Esmtprc }

func (Scanner) Keywords() []string { return []string{"password"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range passwordLineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		val := m[1]
		if val == "" {
			val = m[2]
		}
		if len(val) < 4 {
			continue
		}
		if isPlaceholder(val) {
			continue
		}
		if _, dup := seen[val]; dup {
			continue
		}
		seen[val] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Esmtprc,
			Raw:          []byte(val),
			Redacted:     redact(val),
			Severity:     detectors.SeverityHigh,
		})
	}

	return out, nil
}

func redact(s string) string {
	if len(s) <= 4 {
		return "..."
	}
	return s[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
