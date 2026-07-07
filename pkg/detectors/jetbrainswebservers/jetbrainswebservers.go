// Package jetbrainswebservers detects the JetBrains IDE deploy-target
// credential stored in `.idea/WebServers.xml`'s `<fileTransfer>`
// element: `<fileTransfer host="..." password="..." username="...">`
// (attribute order is not fixed by the schema, so the match is scoped
// to the whole opening tag rather than assuming a position).
//
// JetBrains IDEs can store this attribute either as plaintext or, when
// "Save password" uses the IDE's legacy (pre-PasswordSafe) storage, as
// the output of JetBrains' own `PasswordUtil.encodePassword` — a
// reversible per-character XOR-with-rolling-key scheme, not real
// encryption, that always renders as a hex string. This detector does
// not attempt to decode that scheme: implementing an undocumented,
// version-drifted internal cipher risks a wrong decode that is worse
// than surfacing nothing, and — as with unixcrypthash's password
// hashes — the obfuscated attribute value itself is already a
// meaningful finding (it identifies exactly which account/host pair
// leaked, and is trivially reversible by anyone who has read the same
// open-source JetBrains code this comment is describing).
//
// Verify is deliberately not implemented (class b): the host is
// data-controlled and arbitrary (any SFTP/FTP/deploy target a
// developer configured), so there is no fixed provider to probe.
package jetbrainswebservers

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// fileTransferTagRe captures a whole `<fileTransfer ...>` opening tag so
// the password attribute can be found regardless of attribute order.
var fileTransferTagRe = regexp.MustCompile(`(?is)<fileTransfer\b([^>]{0,1000})>`)

var passwordAttrRe = regexp.MustCompile(`(?i)\bpassword\s*=\s*"([^"]*)"`)
var hostAttrRe = regexp.MustCompile(`(?i)\bhost\s*=\s*"([^"]*)"`)
var usernameAttrRe = regexp.MustCompile(`(?i)\busername\s*=\s*"([^"]*)"`)

var placeholders = map[string]struct{}{
	"password":    {},
	"changeme":    {},
	"change_me":   {},
	"example":     {},
	"placeholder": {},
	"secret":      {},
	"test":        {},
	"testing":     {},
	"dummy":       {},
	"sample":      {},
	"none":        {},
	"null":        {},
	"x":           {},
	"xxx":         {},
	"":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JetBrainsWebServers }

func (Scanner) Keywords() []string { return []string{"filetransfer", "password"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, tag := range fileTransferTagRe.FindAllStringSubmatch(str, -1) {
		if len(tag) < 2 {
			continue
		}
		attrs := tag[1]
		pm := passwordAttrRe.FindStringSubmatch(attrs)
		if pm == nil {
			continue
		}
		val := pm[1]
		if len(val) < 4 {
			continue
		}
		if isPlaceholder(val) {
			continue
		}
		if _, dup := seen[val]; dup {
			continue
		}
		seen[val] = struct{}{}
		extra := map[string]string{}
		if hm := hostAttrRe.FindStringSubmatch(attrs); hm != nil {
			extra["host"] = hm[1]
		}
		if um := usernameAttrRe.FindStringSubmatch(attrs); um != nil {
			extra["username"] = um[1]
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.JetBrainsWebServers,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		})
	}

	return out, nil
}

func redact(s string) string {
	if len(s) <= 8 {
		return "..."
	}
	return s[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
