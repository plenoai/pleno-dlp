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
// Verify is intentionally not performed. Azure SQL speaks TDS (port 1433),
// not HTTP, so there is no HTTP endpoint that would accept these
// credentials — any HTTP probe would be the wrong mechanism and could
// never yield a correct Verified result. A correct TDS login check would
// require a new SQL driver dependency (microsoft/go-mssqldb) needing
// architect sign-off, and is unreliable anyway: Azure SQL's default server
// firewall blocks unknown source IPs, so most live attempts fail with a
// firewall error indistinguishable from invalid credentials, while also
// leaving authentication-failure entries in the operator's audit logs.
// Database-admin credentials warrant SeverityCritical.
//
// The host IS derivable from the chunk: the regex requires the
// database.windows.net host marker and serverRe extracts the fully
// qualified hostname into ExtraData["server"]. Verify is infeasible for
// the TDS/firewall/dependency reasons above, not because the host is
// missing.
package azuresqlconn

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// minPasswordEntropy rejects low-entropy dictionary placeholders
// (your_password, changeme, password) while keeping real DB passwords.
// SQL passwords mix case/digits/symbols; ~3.0 bits/char is a safe floor.
const minPasswordEntropy = 3.0

// Match a connection-string segment that includes the windows.net SQL
// host and a Password key in close vicinity.
//
// Hardening vs. the original generic [A-Za-z]+ key + {0,8} span:
//   - The leading key is anchored to plausible host-bearing connection
//     string keywords (Server / Data Source / Address / Addr /
//     Network Address) so a stray `Foo=...windows.net` no longer opens
//     the span.
//   - The cross-segment window is reduced from {0,8} to {0,3} so a host
//     from one connection string cannot pair with a Password belonging to
//     an adjacent concatenated connection string several segments away.
var connRe = regexp.MustCompile(`(?is)((?:Server|Data\s+Source|Address|Addr|Network\s+Address)\s*=\s*[^;]*\b[a-z0-9-]+\.database\.windows\.net[^;]*;(?:[^;]*;){0,3}?\s*Password\s*=\s*([^;\s"'<>]+))`)

// placeholders are interpolation tokens or template values that must never
// be emitted as a Critical secret. Compared case-insensitively after the
// surrounding wrappers are normalised.
var placeholders = map[string]struct{}{
	"your_password":      {},
	"your_password_here": {},
	"yourpassword":       {},
	"changeme":           {},
	"password":           {},
	"passwd":             {},
	"pass":               {},
	"secret":             {},
	"example":            {},
	"placeholder":        {},
}

// isPlaceholder reports whether p is a template/placeholder/interpolation
// token that should not be treated as a real secret.
func isPlaceholder(p string) bool {
	lp := strings.ToLower(strings.TrimSpace(p))
	if lp == "" {
		return true
	}
	if _, ok := placeholders[lp]; ok {
		return true
	}
	// Bracketed / angle / brace placeholders: <password>, {password},
	// {{ .Password }}, [password].
	if (strings.HasPrefix(lp, "<") && strings.HasSuffix(lp, ">")) ||
		(strings.HasPrefix(lp, "[") && strings.HasSuffix(lp, "]")) ||
		(strings.HasPrefix(lp, "{") && strings.HasSuffix(lp, "}")) {
		return true
	}
	// Shell / CI env-var interpolation: ${DB_PASSWORD}, $(DB_PASSWORD),
	// %PASSWORD%, $PASSWORD.
	if strings.HasPrefix(lp, "${") || strings.HasPrefix(lp, "$(") ||
		strings.HasPrefix(lp, "$") {
		return true
	}
	if strings.HasPrefix(lp, "%") && strings.HasSuffix(lp, "%") {
		return true
	}
	return false
}

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
		// Reject template/placeholder/interpolation passwords and
		// low-entropy dictionary placeholders that slip past the literal
		// list (e.g. "Password1").
		if isPlaceholder(password) {
			continue
		}
		if !detectors.HasMinEntropy(password, minPasswordEntropy) {
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
