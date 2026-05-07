// Package basicauth detects HTTP/HTTPS URLs with embedded Basic-auth
// userinfo (`https://user:password@host`). Detection is deliberately
// conservative: the URL must include `://`, a `:` inside userinfo, and a
// terminating `@`. We refuse to match `mailto:` (which is not Basic auth)
// and reject empty user or password spans.
//
// Verify is intentionally not performed — the host is unbounded and any
// probe risks contacting an unrelated production system. So basicauth
// surfaces unverified-by-design at SeverityMedium. Operators commonly
// strip these credentials by rotating them and re-issuing the URL; the
// password span is the Raw secret and the full URL is RawV2.
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
			}
			extra["scheme"] = scheme
		}
		// Refuse credentials whose user span is empty — empty userinfo is
		// almost always a config-template marker, not a real leak.
		if user == "" {
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
