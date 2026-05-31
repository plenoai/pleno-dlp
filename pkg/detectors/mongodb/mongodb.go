// Package mongodb detects MongoDB connection URIs that embed a password
// (`mongodb://user:password@host` or `mongodb+srv://user:password@host`).
// The password span is the Raw secret; the full URI is RawV2.
//
// Verify is intentionally not performed. Probing the host (including SRV
// lookup for clusters) is tenant-specific and would leave audit-log
// entries on the cluster itself. So mongodb surfaces unverified-by-design
// at SeverityHigh. Note: this is distinct from `mongodbatlas` which
// detects management-plane Atlas API keys.
package mongodb

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `mongodb+srv://` requires escaping the `+` in regex.
var uriRe = regexp.MustCompile(`\b(mongodb(?:\+srv)?://[^\s"'<>]*?:([^\s"'<>@/]+)@[^\s"'<>]+)`)

// placeholderPasswords are documentation/template/quickstart values that
// produce syntactically-perfect MongoDB URIs but are never real secrets.
// Compared case-insensitively against the captured password span. The
// provider keyword gate is tight, but docker-compose and README snippets
// routinely embed these, so we drop them rather than emit SeverityHigh
// noise. (Verify is infeasible here — see package doc — so this denylist
// is the only available FP control.)
var placeholderPasswords = map[string]struct{}{
	"password":      {},
	"passwd":        {},
	"pass":          {},
	"changeme":      {},
	"example":       {},
	"secret":        {},
	"your_password": {},
	"your-password": {},
	"yourpassword":  {},
	"mypassword":    {},
	"test":          {},
	"admin":         {},
	"root":          {},
	"placeholder":   {},
	"xxx":           {},
	"redacted":      {},
}

// exampleHosts are well-known local/example deployment targets. A
// placeholder password pointed at one of these is conclusively a
// quickstart/compose snippet, not a real leaked credential.
var exampleHosts = map[string]struct{}{
	"localhost":        {},
	"127.0.0.1":        {},
	"mongo":            {},
	"db":               {},
	"::1":              {},
	"host.example.com": {},
}

// minPasswordEntropy is a deliberately LOW Shannon-entropy floor
// (bits/char). It exists only to drop extreme-repetition placeholders such
// as "aaaa" (entropy 0) while retaining legitimate short real passwords —
// the existing "p4ss" fixture sits at ~1.50, so the floor is set well
// below it to avoid false negatives on valid short secrets.
const minPasswordEntropy = 1.2

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MongoDB }

func (Scanner) Keywords() []string { return []string{"mongodb://", "mongodb+srv://"} }

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
		// url.Parse rejects `mongodb+srv` opaque, but the standard scheme
		// shape we accept here parses fine when we substitute mongodb+srv
		// for mongodbsrv. Use a simple manual host parse instead so we
		// don't depend on net/url quirks.
		if h, u := manualHostUser(uri); h != "" {
			extra["host"] = h
			if u != "" {
				extra["user"] = u
			}
		} else if pu, err := url.Parse(uri); err == nil {
			if pu.Host != "" {
				extra["host"] = pu.Host
			}
			if pu.User != nil {
				if name := pu.User.Username(); name != "" {
					extra["user"] = name
				}
			}
		}
		// FP control (hardening only — never widens the regex):
		//   1. drop documentation/template placeholder passwords outright;
		//   2. drop a low-entropy extreme-repetition password ("aaaa");
		//   3. belt-and-suspenders: a placeholder pointed at a well-known
		//      example/local host is conclusively a quickstart snippet.
		// (3) is subsumed by (1) today but is kept explicit so that
		// loosening the denylist later still suppresses compose snippets.
		if isPlaceholderPassword(password) {
			continue
		}
		if !detectors.HasMinEntropy(password, minPasswordEntropy) {
			continue
		}
		if host := stripPort(extra["host"]); isExampleHost(host) && isPlaceholderPassword(password) {
			continue
		}
		if strings.HasPrefix(uri, "mongodb+srv://") {
			extra["srv"] = "true"
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.MongoDB,
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

// manualHostUser splits `scheme://user:password@host[/path]` into (host,
// user) without depending on net/url's handling of `+srv`.
func manualHostUser(uri string) (string, string) {
	idx := strings.Index(uri, "://")
	if idx < 0 {
		return "", ""
	}
	rest := uri[idx+3:]
	at := strings.Index(rest, "@")
	if at < 0 {
		return "", ""
	}
	userinfo := rest[:at]
	hostpath := rest[at+1:]
	host := hostpath
	if slash := strings.Index(hostpath, "/"); slash >= 0 {
		host = hostpath[:slash]
	}
	if q := strings.Index(host, "?"); q >= 0 {
		host = host[:q]
	}
	user := ""
	if colon := strings.Index(userinfo, ":"); colon >= 0 {
		user = userinfo[:colon]
	}
	return host, user
}

func isPlaceholderPassword(pw string) bool {
	_, ok := placeholderPasswords[strings.ToLower(pw)]
	return ok
}

func isExampleHost(host string) bool {
	_, ok := exampleHosts[strings.ToLower(host)]
	return ok
}

// stripPort removes a trailing `:port` so host comparisons match
// regardless of whether the URI pinned a port (e.g. `localhost:27017`).
func stripPort(host string) string {
	if colon := strings.LastIndex(host, ":"); colon >= 0 {
		return host[:colon]
	}
	return host
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
