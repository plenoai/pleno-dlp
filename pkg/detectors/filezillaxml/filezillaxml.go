// Package filezillaxml detects FileZilla's stored-site-manager password
// element: `<Pass>plaintext</Pass>` (filezilla.xml, when no FileZilla
// master password is set) and `<Pass encoding="base64">...</Pass>`
// (recentservers.xml, and filezilla.xml when FileZilla's own weak
// "protect" scheme applied a base64 wrapping — note this is FileZilla's
// own optional obfuscation layer, not real encryption; a base64-wrapped
// value is decoded before the deny-list check below runs against the
// underlying bytes).
//
// Verify is deliberately not implemented (class b): the credential
// authenticates against the arbitrary FTP/SFTP host stored elsewhere in
// the same <Server> block, not a fixed provider endpoint.
package filezillaxml

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// passTagRe matches a <Pass>...</Pass> element, optionally carrying a
// FileZilla `encoding="base64"` attribute. `[^<]*` for the body is
// sufficient — FileZilla never escapes `<` inside this element.
var passTagRe = regexp.MustCompile(
	`(?i)<Pass(?:\s+encoding="([^"]*)")?\s*>([^<]*)</Pass>`,
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

func (Scanner) Type() detectors.DetectorType { return detectors.FileZillaXML }

func (Scanner) Keywords() []string { return []string{"<pass", "filezilla"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range passTagRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		encoding, body := m[1], strings.TrimSpace(m[2])
		val := body
		if strings.EqualFold(encoding, "base64") {
			decoded, err := base64.StdEncoding.DecodeString(body)
			if err != nil {
				continue
			}
			val = strings.TrimSpace(string(decoded))
		}
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
		out = append(out, detectors.Result{
			DetectorType: detectors.FileZillaXML,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"encoding": encoding,
			},
			Severity: detectors.SeverityHigh,
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
