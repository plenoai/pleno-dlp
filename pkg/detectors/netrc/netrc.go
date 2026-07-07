// Package netrc detects `.netrc` / `_netrc` credential entries: the
// `machine <host> login <user> password <pass>` token grammar (RFC
// unspecified, but stable since 4.2BSD ftp(1)) used by curl, ftp, git's
// credential.helper=netrc, and countless CI systems. `default` entries
// (`default login <user> password <pass>`, matching any host) are
// covered too. `login` and `password` may appear in either order
// within an entry.
//
// Unlike the other extractors in this batch, netrc entries carry a
// literal `password` token, so this detector uses the engine's normal
// keyword-anchored vicinity dispatch rather than FullChunkDetector —
// no whole-chunk regex cost.
//
// macdef (netrc macro) blocks are out of scope: they hold arbitrary
// shell text until a blank line, not a fixed token grammar, and
// scanning them would need multi-line state this detector does not
// track.
//
// Verify is deliberately not implemented (class b): the host is
// data-controlled and arbitrary (mail, FTP, or any HTTP endpoint a
// user configured), so there is no fixed provider to probe.
package netrc

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// netrcEntryRe anchors on a `machine <host>` or `default` token,
// followed by `login`/`password` in either order within the same
// entry. `\S+` for the host/login/password values stops at the next
// token boundary, so this cannot bleed into a following entry.
var netrcEntryRe = regexp.MustCompile(
	`(?i)(?:\bmachine[ \t]+\S+|\bdefault\b)[ \t\r\n]+` +
		`(?:login[ \t]+(\S+)[ \t\r\n]+password[ \t]+(\S+)` +
		`|password[ \t]+(\S+)[ \t\r\n]+login[ \t]+(\S+))`,
)

var placeholders = map[string]struct{}{
	"password":    {},
	"passwd":      {},
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

func (Scanner) Type() detectors.DetectorType { return detectors.Netrc }

func (Scanner) Keywords() []string { return []string{"password", "machine"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range netrcEntryRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 5 {
			continue
		}
		var login, pass string
		if m[1] != "" || m[2] != "" {
			login, pass = m[1], m[2]
		} else {
			pass, login = m[3], m[4]
		}
		if pass == "" {
			continue
		}
		if isPlaceholder(pass) {
			continue
		}
		if pass == login {
			continue
		}
		key := login + "\x00" + pass
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		extra := map[string]string{}
		if login != "" {
			extra["login"] = login
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.Netrc,
			Raw:          []byte(pass),
			Redacted:     redact(pass),
			ExtraData:    extra,
			Severity:     detectors.SeverityHigh,
		})
	}

	return out, nil
}

func redact(s string) string {
	if len(s) <= 4 {
		return "..."
	}
	return s[:2] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
