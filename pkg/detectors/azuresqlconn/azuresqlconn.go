// Package azuresqlconn detects Azure SQL Database connection strings.
// The canonical shape is:
//
//	Server=tcp:<server>.database.windows.net,1433;Initial Catalog=<db>;
//	  Persist Security Info=False;User ID=<u>;Password=<p>;...
//
// We require the `database.windows.net` host marker plus a Password key —
// the combination is highly specific. The password is the Raw secret;
// the full connection string is RawV2 so reviewers can rotate the right
// account without losing context.
//
// Verify is intentionally not performed. The host is tenant-specific and
// probing it leaves authentication-failure entries in the operator's
// audit logs. Database-admin credentials warrant SeverityCritical.
package azuresqlconn

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Match a connection-string segment that includes the windows.net SQL
// host and a Password key in the same span.
var connRe = regexp.MustCompile(`(?is)([A-Za-z]+\s*=\s*[^;]*\b[a-z0-9-]+\.database\.windows\.net[^;]*;[^;]*?(?:[^;]*;){0,8}?\s*Password\s*=\s*([^;\s"'<>]+))`)

// Canonical key extractors for ExtraData. Used after a candidate match.
var serverRe = regexp.MustCompile(`(?i)Server\s*=\s*(?:tcp:)?\s*([a-z0-9-]+\.database\.windows\.net)(?:,\s*\d+)?`)
var userRe = regexp.MustCompile(`(?i)User\s*ID\s*=\s*([^;\s"'<>]+)`)
var dbRe = regexp.MustCompile(`(?i)(?:Initial\s+Catalog|Database)\s*=\s*([^;\s"'<>]+)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureSQLConnString }

func (Scanner) Keywords() []string { return []string{"database.windows.net"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := connRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		conn := string(m[1])
		password := string(m[2])
		if password == "" {
			continue
		}
		if _, dup := seen[conn]; dup {
			continue
		}
		seen[conn] = struct{}{}
		extra := map[string]string{}
		if sm := serverRe.FindStringSubmatch(conn); len(sm) == 2 {
			extra["server"] = strings.ToLower(sm[1])
		}
		if um := userRe.FindStringSubmatch(conn); len(um) == 2 {
			extra["user_id"] = um[1]
		}
		if dm := dbRe.FindStringSubmatch(conn); len(dm) == 2 {
			extra["database"] = dm[1]
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.AzureSQLConnString,
			Raw:          []byte(password),
			RawV2:        []byte(conn),
			Redacted:     redact(password),
			ExtraData:    extra,
			Severity:     detectors.SeverityCritical,
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
