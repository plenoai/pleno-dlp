// Package basicauth detects HTTP/HTTPS URLs with embedded Basic-auth
// userinfo (`https://user:password@host`). Detection is deliberately
// conservative: the URL must include `://`, a `:` inside userinfo, and a
// terminating `@`. We refuse to match `mailto:` (which is not Basic auth)
// and reject empty user or password spans.
//
// Verify is intentionally not performed (unverified-by-design, class b).
// The host span is fully data-controlled and arbitrary, so issuing a
// Basic-auth probe would be an SSRF/blind-probe against an unrelated
// production system. There is also no provider-fixed endpoint and no
// known accept/reject status-code convention for an arbitrary host: a
// server that returns 200 regardless of the Authorization header would
// yield a false Verified=true. Live verification is therefore infeasible
// and would be incorrect to implement. basicauth surfaces at
// SeverityMedium; the password span is the Raw secret and the full URL is
// RawV2.
//
// Because there is no verify backstop, the regex alone is noisy:
// documentation and config templates routinely embed non-empty userinfo
// such as `https://username:password@host` or `https://admin:${DB_PASS}@h`.
// To suppress those without dropping short-but-real passwords, basicauth
// applies, after url.Parse (so percent-encoded passwords are decoded):
//   - a templating-delimiter gate: userinfo containing { } < > $ % is a
//     placeholder, never a literal credential;
//   - a case-insensitive placeholder denylist on both the user and the
//     password span (password, secret, changeme, x-oauth-basic, ...);
//   - a minimum Shannon-entropy gate on the password to drop low-entropy
//     doc fillers, with the denylist covering high-entropy placeholders
//     (e.g. "password") that clear the entropy bar.
//
// To keep noise down, basicauth skips URIs whose scheme is owned by a
// dedicated detector in this package (postgres, mysql, mongodb, redis,
// rabbitmq, smtp). Those have their own severity calibration and parsing.
package basicauth

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Match generic http(s) URLs (and ftp/ftps) with userinfo. The `:`
// inside userinfo and `@` terminator are mandatory.
var uriRe = regexp.MustCompile(`\b((?:https?|ftps?)://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// minPasswordEntropy drops low-entropy documentation fillers (e.g. "bar",
// "abc") while keeping short-but-real passwords. Set deliberately low (2.5
// bits/byte): high-entropy placeholders such as "password" clear this bar
// and are caught by the denylist below instead.
const minPasswordEntropy = 2.5

// placeholders are common documentation/template credential words. Compared
// case-insensitively against both the user and password spans; a match on
// either side drops the finding.
var placeholders = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"pwd":           {},
	"secret":        {},
	"changeme":      {},
	"example":       {},
	"placeholder":   {},
	"your_password": {},
	"yourpassword":  {},
	"xxx":           {},
	"x-oauth-basic": {},
	"token":         {},
	"credentials":   {},
	"admin":         {},
	"test":          {},
}

// templating delimiters that mark a span as a placeholder, not a literal
// credential: ${VAR}, {{var}}, <password>, %VAR%, {var}.
const templatingDelims = "{}<>$%"

func isPlaceholder(s string) bool {
	_, ok := placeholders[strings.ToLower(s)]
	return ok
}

func hasTemplatingDelim(s string) bool {
	return strings.ContainsAny(s, templatingDelims)
}

// Schemes already covered by their own detector — drop those to avoid
// duplicate findings under different DetectorTypes.
var ownedSchemes = map[string]struct{}{
	"postgres":   {},
	"postgresql": {},
	"mysql":      {},
	"mysqlx":     {},
	"mongodb":    {},
	"redis":      {},
	"rediss":     {},
	"amqp":       {},
	"amqps":      {},
	"smtp":       {},
	"smtps":      {},
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BasicAuth }

func (Scanner) Keywords() []string { return []string{"http://", "https://", "ftp://", "ftps://"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := uriRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		uri := string(m[1])
		// Raw (possibly percent-encoded) password span from the regex; the
		// decoded value from url.Parse is preferred when parsing succeeds.
		password := string(m[2])
		if password == "" {
			continue
		}
		if _, dup := seen[uri]; dup {
			continue
		}
		seen[uri] = struct{}{}
		extra := map[string]string{}
		var user string
		if u, err := url.Parse(uri); err == nil {
			scheme := strings.ToLower(u.Scheme)
			if _, owned := ownedSchemes[scheme]; owned {
				continue
			}
			if u.Host != "" {
				extra["host"] = u.Host
			}
			if u.User != nil {
				if name := u.User.Username(); name != "" {
					user = name
					extra["user"] = name
				}
				// Prefer the decoded password so percent-encoded values are
				// gated and reported in their literal form.
				if pw, set := u.User.Password(); set && pw != "" {
					password = pw
				}
			}
			extra["scheme"] = scheme
		}
		// Refuse credentials whose user span is empty — empty userinfo is
		// almost always a config-template marker, not a real leak.
		if user == "" {
			continue
		}
		// Templating markers (${VAR}, {{var}}, <password>, %VAR%) in either
		// span mean this is a config template, not a literal credential.
		if hasTemplatingDelim(user) || hasTemplatingDelim(password) {
			continue
		}
		// Common documentation placeholder words on either side — drop. This
		// also catches high-entropy placeholders (e.g. "password") that would
		// otherwise clear the entropy gate below.
		if isPlaceholder(user) || isPlaceholder(password) {
			continue
		}
		// Low-entropy passwords ("bar", "abc") are doc fillers, not secrets.
		if !detectors.HasMinEntropy(password, minPasswordEntropy) {
			continue
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.BasicAuth,
			Raw:          []byte(password),
			RawV2:        []byte(uri),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityMedium,
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
