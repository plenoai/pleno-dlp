// Package unixcrypthash detects `username:hash` password-hash lines:
// Apache/nginx `.htpasswd`, ProFTPD's flat-file passwd db
// (`proftpdpasswd` and similar), and `/etc/shadow`-style entries.
// These carry no "password" keyword — the credential signal is
// entirely in the hash's own format tag (`$6$`, `$2y$`, `{SHA}`, ...)
// plus the `user:` prefix that anchors it to an account.
//
// A leaked password hash is a real finding even though it is not
// directly usable: it is an offline-crackable secret (dictionary/rule
// attack against weak passwords) and, for the reused-hash case, is
// itself a credential across any system sharing the same hash. This
// mirrors gitleaks/trufflehog conventions of surfacing crypt-format
// hashes as findings, not filtering them out as "not a real secret".
//
// The recognized hash formats double as this detector's Keywords():
// `$1$`/`$5$`/`$6$`/`$apr1$` (glibc/Apache crypt), `$2a$`/`$2b$`/`$2y$`
// (bcrypt), and the legacy Apache `{SHA}`/`{SSHA}`/`{MD5}` tags. Since
// these are literal, low-collision substrings that appear directly in
// the matched text, this detector uses the engine's normal
// keyword-anchored vicinity dispatch rather than FullChunkDetector.
//
// Verify is deliberately not implemented (class b): a password hash is
// not a bearer credential against any fixed provider endpoint — there
// is nothing to call.
package unixcrypthash

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// cryptLineRe matches `user:hash` optionally followed by more
// colon-delimited fields (the /etc/shadow aging fields, or ProFTPD's
// uid/gid/home/shell tail) — those extra fields are matched but not
// captured. The username charset covers typical POSIX account names;
// the hash alternation covers glibc/Apache modular crypt ($id$salt$hash),
// bcrypt ($2[aby]$rounds$payload), and legacy Apache curly-brace tags.
var cryptLineRe = regexp.MustCompile(
	`(?m)^([A-Za-z0-9_][A-Za-z0-9_.\-]{0,31}):` +
		`(\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}` +
		`|\$(?:1|5|6|apr1)\$[A-Za-z0-9./]{1,16}\$[A-Za-z0-9./]{20,100}` +
		`|(?i:\{(?:SSHA|SHA|MD5)\})[A-Za-z0-9+/=]{10,100})` +
		`(?::[^\n]*)?[ \t]*$`,
)

// knownExampleHashes are widely published tutorial/library sample
// hashes (bcryptjs README, Apache docs, etc.) that get copy-pasted into
// READMEs and test fixtures across the internet. They are not tied to
// any real account and would otherwise be a predictable source of
// noise on OSS repos that quote them verbatim.
var knownExampleHashes = map[string]struct{}{
	// bcryptjs / node.bcrypt.js README example: bcrypt.hashSync("bacon", 10)
	"$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy": {},
	"$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy": {},
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.UnixCryptHash }

func (Scanner) Keywords() []string {
	return []string{"$apr1$", "$1$", "$5$", "$6$", "$2a$", "$2b$", "$2y$", "{sha}", "{ssha}", "{md5}"}
}

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	str := string(data)
	seen := map[string]struct{}{}
	var out []detectors.Result

	for _, m := range cryptLineRe.FindAllStringSubmatch(str, -1) {
		if len(m) < 3 {
			continue
		}
		user, hash := m[1], m[2]
		if _, known := knownExampleHashes[hash]; known {
			continue
		}
		key := user + ":" + hash
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.UnixCryptHash,
			Raw:          []byte(hash),
			Redacted:     redact(hash),
			ExtraData: map[string]string{
				"user": user,
			},
			Severity: detectors.SeverityHigh,
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
