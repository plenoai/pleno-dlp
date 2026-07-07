// Package npmrcauth detects npm's `.npmrc` credential directives:
// `_auth = <base64(user:pass)>` (npm's legacy combined Basic-auth
// blob), `_authToken = <token>` (the modern bearer form, optionally
// scoped to a registry as `//<registry>/:_authToken=<token>`), and
// `_password = <base64(pass)>`.
//
// `_auth`'s value is npm's own base64(username:password) encoding, used
// directly as an HTTP Basic-Auth header — not a hash, not encryption.
// When it decodes to a "user:pass" pair whose password half is a
// well-known documentation placeholder (the `admin:admin` /
// `user:pass` examples that get copy-pasted from npm's own docs into
// countless example `.npmrc` files), this detector suppresses it the
// same way the other structured extractors in this issue suppress
// literal "password" placeholders; otherwise the base64 blob itself —
// which is what npm sends over the wire — is reported as the secret.
//
// Verify is deliberately not implemented (class b): the registry host
// (npmjs.org, a private Verdaccio/Artifactory mirror, ...) is
// data-controlled and arbitrary.
package npmrcauth

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// npmrcLineRe matches one `.npmrc` auth directive line, with an optional
// `//<registry>/:` scope prefix ahead of the key.
var npmrcLineRe = regexp.MustCompile(
	`(?im)^[ \t]*(?:\/\/\S*\/:)?(_auth|_authToken|_password)\s*=\s*(\S+)[ \t]*$`,
)

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
	"admin":       {},
	"pass":        {},
	"x":           {},
	"xxx":         {},
	"":            {},
}

func isPlaceholder(v string) bool {
	_, ok := placeholders[strings.ToLower(v)]
	return ok
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.NpmrcAuth }

func (Scanner) Keywords() []string { return []string{"_auth", "_authtoken", "_password"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range npmrcLineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		key, val := m[1], m[2]
		if len(val) < 4 {
			continue
		}
		if strings.EqualFold(key, "_auth") && isPlaceholderBasicAuth(val) {
			continue
		}
		if isPlaceholder(val) {
			continue
		}
		dedupKey := strings.ToLower(key) + "\x00" + val
		if _, dup := seen[dedupKey]; dup {
			continue
		}
		seen[dedupKey] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.NpmrcAuth,
			Raw:          []byte(val),
			Redacted:     redact(val),
			ExtraData: map[string]string{
				"key": key,
			},
			Severity: detectors.SeverityHigh,
		})
	}

	return out, nil
}

// isPlaceholderBasicAuth reports whether npm's `_auth` base64 blob
// decodes to a "user:pass" pair whose password half is a known
// documentation placeholder. Decode failures and non "user:pass"
// shapes are not placeholders — the raw blob is reported as-is.
func isPlaceholderBasicAuth(b64 string) bool {
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false
	}
	return isPlaceholder(parts[1]) || isPlaceholder(parts[0])
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
