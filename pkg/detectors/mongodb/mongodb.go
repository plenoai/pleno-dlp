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

func redact(t string) string {
	if len(t) <= 4 {
		return "..."
	}
	return t[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
