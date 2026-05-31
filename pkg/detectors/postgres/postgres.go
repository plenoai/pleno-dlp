// Package postgres detects PostgreSQL connection URIs that embed a password
// (`postgres://user:password@host` or `postgresql://…`). The password span is
// the Raw secret; the full URI is RawV2 so reviewers can rotate without
// exposing host metadata in the primary view.
//
// Verify is intentionally not performed. The only meaningful "verify" for a
// connection string is a live PostgreSQL dial against the embedded host, which
// is a tenant-specific production database. A successful dial observably
// authenticates the scanner as the credential owner against a third-party
// production DB, and a failed dial leaves authentication-failure entries in the
// operator's logs. That destructive/observable side effect is one the team
// deliberately declines (the same stance shared by the whole connection-string
// family: mysql, mongodb, redis, rabbitmq, smtp). The `@host` segment *is*
// present in the chunk — the regex requires it and FromData parses it into
// ExtraData["host"] — so the historical "host not in chunk" rationale was
// wrong; the real reason is the won't-probe-tenant-production-DB policy above.
// So postgres surfaces unverified-by-design at SeverityHigh.
//
// Because the match is surfaced unverified, placeholder/example connection
// strings carry real false-positive risk (README quickstarts, docker-compose
// defaults, env-var templates in config files). FromData therefore applies a
// semantic gate on the captured password span: a case-insensitive sentinel
// denylist, a pure-template-marker exclusion (`${...}`, `{{...}}`, `%(...)s`,
// `<...>`), and a minimal Shannon-entropy floor that rejects degenerate runs
// like `aaaa`. The entropy floor is intentionally low: real short passwords
// such as `s3cr3t` sit around 2.25 bits/char, so a higher gate would discard
// genuine secrets. The denylist — not entropy — separates the literal
// `password`/`postgres`/`changeme` family from real credentials.
package postgres

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Both `postgres://` and `postgresql://` schemes are accepted. Userinfo is
// required (`:` and `@`).
var uriRe = regexp.MustCompile(`\b(postgres(?:ql)?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// passwordDenylist holds case-insensitive literal placeholder/sentinel values
// that appear in documentation and compose defaults rather than as real
// secrets. Entropy cannot separate these from genuine short passwords
// (`password`, `postgres`, `changeme` all sit at ~2.75 bits/char, the same band
// as a real `s3cr3t`), so an explicit denylist is the load-bearing filter.
var passwordDenylist = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"postgres":      {},
	"postgresql":    {},
	"example":       {},
	"changeme":      {},
	"change_me":     {},
	"changethis":    {},
	"secret":        {},
	"mysecret":      {},
	"your_password": {},
	"yourpassword":  {},
	"placeholder":   {},
	"admin":         {},
	"root":          {},
	"test":          {},
	"hunter2":       {},
}

// templateMarkerRe matches a password span that is entirely an interpolation /
// template placeholder rather than a literal value: `${DB_PASS}`, `{{password}}`,
// `%(password)s`, or `<password>`. Such spans denote config templates where no
// literal secret is present.
var templateMarkerRe = regexp.MustCompile(`^(?:\$\{[^}]*\}|\{\{[^}]*\}\}|%\([^)]*\)s|<[^>]*>)$`)

// minPasswordEntropy rejects only degenerate spans (e.g. `aaaa`, `0000`). It is
// deliberately well below the entropy of real short passwords so it never
// discards a genuine secret; the denylist handles dictionary placeholders.
const minPasswordEntropy = 1.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Postgres }

func (Scanner) Keywords() []string { return []string{"postgres://", "postgresql://"} }

// isPlaceholderPassword reports whether the captured password span is a
// documentation placeholder / template marker / degenerate value rather than a
// plausible literal secret.
func isPlaceholderPassword(password string) bool {
	if _, deny := passwordDenylist[strings.ToLower(password)]; deny {
		return true
	}
	if templateMarkerRe.MatchString(password) {
		return true
	}
	// Degenerate low-information spans (repeated chars) are not secrets.
	if !detectors.HasMinEntropy(password, minPasswordEntropy) {
		return true
	}
	return false
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := uriRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		uri := string(m[1])
		password := string(m[2])
		if password == "" {
			continue
		}
		// Suppress documentation placeholders / config templates: these are
		// surfaced unverified at SeverityHigh, so a literal `password` or a
		// `${DB_PASSWORD}` template would otherwise be pure noise.
		if isPlaceholderPassword(password) {
			continue
		}
		if _, dup := seen[uri]; dup {
			continue
		}
		seen[uri] = struct{}{}
		extra := map[string]string{}
		if u, err := url.Parse(uri); err == nil {
			if u.Host != "" {
				extra["host"] = u.Host
			}
			if u.User != nil {
				if name := u.User.Username(); name != "" {
					extra["user"] = name
				}
			}
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.Postgres,
			Raw:          []byte(password),
			RawV2:        []byte(uri),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func redact(t string) string {
	if len(t) <= 4 {
		return "..."
	}
	return t[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
