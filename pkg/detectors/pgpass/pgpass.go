// Package pgpass detects PostgreSQL `.pgpass` credential lines:
// `hostname:port:database:username:password` (libpq's PGPASSFILE
// format). The password carries no keyword or entropy signal of its
// own — it is the fifth colon-delimited field, full stop — so this
// detector keys entirely on line shape rather than on Keywords().
//
// The Detector interface never receives the source filename, so
// "structured config-file extraction" here means "content shape only":
// the same shape-matching applies whether the bytes came from a file
// literally named .pgpass, from stdin, or from a git blob. A `#`-led
// comment line (the conventional `#hostname:port:database:username:password`
// header some pgpass files carry) is excluded implicitly: `#` is not in
// the hostname character class below, so the header line never matches
// the data-line pattern.
//
// Because .pgpass has no keyword to anchor a vicinity slice on, this
// detector implements detectors.FullChunkDetector and pays the
// whole-window regex cost on every chunk. The regex is a single
// anchored line pattern with no backtracking risk, so the added cost
// per window is small and bounded.
//
// Verify is deliberately not implemented (class b): the host is
// data-controlled and arbitrary, so a live connection attempt would be
// a blind probe against an unrelated Postgres instance.
package pgpass

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// pgpassLineRe matches one full pgpass data line: five colon-delimited
// fields, no whitespace. hostname/database/username are restricted to
// typical identifier characters (or the pgpass wildcard `*`) and port
// must be numeric or `*`; that structural anchor is what keeps this
// FullChunkDetector from firing on arbitrary five-field colon text
// elsewhere in a scanned file (timestamps and MAC addresses do not have
// exactly four colons with a numeric-or-`*` second field). The password
// field itself only excludes the field separator and newlines — pgpass
// passwords may contain punctuation the other fields cannot.
var pgpassLineRe = regexp.MustCompile(
	`(?m)^[ \t]*([A-Za-z0-9_.\-\*]{1,255}):([0-9]{1,5}|\*):([A-Za-z0-9_.\-\*]{1,63}):([A-Za-z0-9_.\-\*]{1,63}):([^:\r\n]{1,255})[ \t]*$`,
)

// placeholders are values with no real-world credential signal:
// documentation fillers, and the pgpass spec's own field-name ("password")
// leaking into a copy-pasted template. Compared case-insensitively.
var placeholders = map[string]struct{}{
	"password":    {},
	"passwd":      {},
	"pass":        {},
	"changeme":    {},
	"change_me":   {},
	"changeit":    {},
	"example":     {},
	"placeholder": {},
	"secret":      {},
	"test":        {},
	"testing":     {},
	"dummy":       {},
	"sample":      {},
	"none":        {},
	"null":        {},
	"n/a":         {},
	"*":           {},
	"x":           {},
	"xxx":         {},
	"":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pgpass }

// Keywords is documentation-only here: pgpass data lines have no fixed
// literal marker, so dispatch is driven entirely by WantsFullChunk
// below, not by an Aho-Corasick keyword hit.
func (Scanner) Keywords() []string { return []string{"pgpass"} }

// WantsFullChunk opts into the FullChunkDetector path — see the package
// doc comment for why pgpass cannot use a keyword-anchored vicinity
// slice.
func (Scanner) WantsFullChunk() bool { return true }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range pgpassLineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 6 {
			continue
		}
		host, port, db, user, pass := m[1], m[2], m[3], m[4], m[5]
		if isPlaceholder(pass) {
			continue
		}
		// The password field equalling any of the other fields verbatim
		// is a strong signal of a templated example row rather than a
		// real credential (e.g. `host:5432:host:host:host`).
		if pass == host || pass == db || pass == user {
			continue
		}
		key := host + ":" + port + ":" + db + ":" + user + ":" + pass
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Pgpass,
			Raw:          []byte(pass),
			Redacted:     redact(pass),
			ExtraData: map[string]string{
				"host":     host,
				"port":     port,
				"database": db,
				"user":     user,
			},
			Severity: detectors.SeverityHigh,
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
