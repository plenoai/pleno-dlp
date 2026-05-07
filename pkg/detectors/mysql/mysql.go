// Package mysql detects MySQL connection URIs that embed a password
// (`mysql://user:password@host` or `mysqlx://`). The password span is the
// Raw secret; the full URI is RawV2 so reviewers can rotate without exposing
// host metadata in the primary view.
//
// Verify is intentionally not performed. The host is tenant-specific and
// probing it leaves authentication-failure entries in the operator's logs.
// So mysql surfaces unverified-by-design at SeverityHigh.
package mysql

import (
	"context"
	"net/url"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var uriRe = regexp.MustCompile(`\b(mysqlx?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MySQL }

func (Scanner) Keywords() []string { return []string{"mysql://", "mysqlx://"} }

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
			DetectorType: detectors.MySQL,
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
