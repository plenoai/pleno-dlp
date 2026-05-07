// Package postgres detects PostgreSQL connection URIs that embed a password
// (`postgres://user:password@host` or `postgresql://…`). The password span is
// the Raw secret; the full URI is RawV2 so reviewers can rotate without
// exposing host metadata in the primary view.
//
// Verify is intentionally not performed. The database host is tenant-specific
// and probing it leaves authentication-failure entries in the operator's
// logs. So postgres surfaces unverified-by-design at SeverityHigh.
package postgres

import (
	"context"
	"net/url"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Both `postgres://` and `postgresql://` schemes are accepted. Userinfo is
// required (`:` and `@`).
var uriRe = regexp.MustCompile(`\b(postgres(?:ql)?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Postgres }

func (Scanner) Keywords() []string { return []string{"postgres://", "postgresql://"} }

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
