// Package esmtprc detects the `password` line of an `.esmtprc` /
// `~/.esmtprc` config (esmtp(1), the lightweight SMTP relay client, and
// its msmtp/ssmtp-family lookalikes): a bare `key value` grammar, one
// directive per line, where the value is optionally double-quoted
// (`password "hunter2"` or `password hunter2`).
//
// The line-anchored `password` grammar alone is not sufficient: any
// text with a self-contained `password <token>` line — a Go struct
// field declaration (`Password string`), an English sentence that
// happens to end a line right after "password", etc. — satisfies it.
// `.esmtprc` is a one-directive-per-line format with a fixed keyword
// set, so a real file always carries at least one other directive
// alongside `password`. FromData requires the chunk to contain one of
// those sibling directives before any `password` line counts (#293).
//
// Both the `password` grammar and the sibling-directive check are
// case-sensitive lowercase: esmtp(1) directive keywords are always
// lowercase in the on-disk format, whereas the same words in source
// code are conventionally capitalized (an exported Go struct field
// `Password string`) or embedded in a larger expression (a local
// `username = user.Username` assignment) — case-sensitivity plus the
// same full-line, single-token-value anchor on both regexes rejects
// both source-code shapes without needing per-language stopwords.
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

// passwordLineRe matches an esmtprc `password` directive: the lowercase
// keyword, then either a double-quoted value or a bare
// whitespace-delimited token, alone on its line (start-to-end
// anchored, so leading/trailing text on the same line disqualifies
// it).
var passwordLineRe = regexp.MustCompile(
	`(?m)^[ \t]*password[ \t]+(?:"([^"\r\n]*)"|(\S+))[ \t]*$`,
)

// contextDirectiveRe matches a sibling esmtprc directive
// (hostname/username/mda/starttls) using the same self-contained,
// single-token-value, lowercase-keyword grammar as passwordLineRe. A
// `password` line with no sibling directive line anywhere in the chunk
// is not an `.esmtprc` file — it is coincidence.
var contextDirectiveRe = regexp.MustCompile(
	`(?m)^[ \t]*(?:hostname|username|mda|starttls)[ \t]+(?:"[^"\r\n]*"|\S+)[ \t]*$`,
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

	// No sibling esmtprc directive in the chunk: this isn't an
	// .esmtprc file, whatever the password line looks like.
	if !contextDirectiveRe.MatchString(str) {
		return nil, nil
	}

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
