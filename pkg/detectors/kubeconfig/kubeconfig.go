// Package kubeconfig detects kubeconfig YAML containing credential
// material — `client-certificate-data:`, `client-key-data:`, or `token:`
// fields under a `users:` block.
//
// Verify is intentionally not performed and is genuinely infeasible: the
// matched chunk never carries the cluster `server:` URL into Raw/RawV2,
// the cluster API endpoint is tenant-specific (an arbitrary private
// host/port) and not derivable from the credential (a ServiceAccount
// JWT's `iss` is literally "kubernetes", with no network address), and
// the cert/key path additionally requires the cluster CA + mTLS which is
// not in the chunk. Probing a guessed endpoint would risk a false
// Verified and leaves authentication-failure entries. This mirrors
// trufflehog, which performs no live Verify for kubeconfig material.
// Cluster-admin scope warrants SeverityCritical. The detector emits one
// finding per credential field; Raw is the credential value, RawV2 is
// the surrounding YAML user entry name when discoverable.
//
// Because `kind: Config` is NOT exclusive to kubeconfig (kustomize, CRDs,
// and assorted tooling reuse it), a bare keyword/regex gate over-fires on
// any document that merely contains a `kind: Config` line plus an
// unrelated `token:` placeholder. To keep noise low without losing real
// findings we apply four coordinated guards:
//
//  1. Gate on BOTH a `kind: Config` line AND a kubeconfig-consistent
//     `apiVersion` line (`v1` or a `client.authentication.k8s.io/*`
//     group used by exec/auth plugins).
//  2. Require each credential field to occur within usersVicinity bytes
//     AFTER a `users:` / `user:` block marker, so credential-shaped lines
//     that live under unrelated objects are rejected.
//  3. Apply a Shannon-entropy floor on the credential value to drop
//     human-readable placeholders.
//  4. Reject obvious placeholder fills (REDACTED, changeme, example,
//     your-token-here, xxxxx-style runs) outright.
package kubeconfig

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Gate markers. We require kind: Config AND a kubeconfig-consistent
// apiVersion. `v1` is the canonical kubeconfig apiVersion; the
// client.authentication.k8s.io group appears in exec-credential plugin
// stanzas embedded in real kubeconfigs.
var (
	kindRe       = regexp.MustCompile(`(?im)^\s*kind\s*:\s*Config\s*$`)
	apiVersionRe = regexp.MustCompile(`(?im)^\s*apiVersion\s*:\s*["']?(v1|client\.authentication\.k8s\.io/[^\s"']+)["']?\s*$`)
)

// usersBlockRe locates `users:` / `user:` block markers. A credential
// field only counts when it falls within usersVicinity bytes AFTER one
// of these markers — the inline vicinity check that ties the credential
// to a users block rather than an unrelated object.
var usersBlockRe = regexp.MustCompile(`(?im)^\s*-?\s*users?\s*:\s*$`)

const usersVicinity = 200

// One result per credential field. We anchor on YAML line shape (key
// indented under `user:`) and require a non-empty value.
var (
	clientCertRe = regexp.MustCompile(`(?m)^\s*client-certificate-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
	clientKeyRe  = regexp.MustCompile(`(?m)^\s*client-key-data\s*:\s*([A-Za-z0-9+/=]{40,})\s*$`)
	tokenRe      = regexp.MustCompile(`(?m)^\s*token\s*:\s*([A-Za-z0-9._\-+/=]{20,})\s*$`)
	nameRe       = regexp.MustCompile(`(?m)^[\s-]*name\s*:\s*([^\s]+)\s*$`)
)

// minTokenEntropy drops human-readable placeholder tokens. base64url /
// JWT material clears ~3.5 bits/char comfortably; hyphenated English
// placeholders ("your-bearer-token-here") and runs of one character do
// not. cert/key data is base64 and always clears this; we only gate the
// token field, which is the one with realistic placeholder collisions.
const minTokenEntropy = 3.5

// placeholderHints are substrings that flag a value as an obvious
// non-credential fill. Matched case-insensitively against the value.
var placeholderHints = []string{
	"redacted",
	"changeme",
	"change-me",
	"example",
	"your-token",
	"your-bearer-token",
	"placeholder",
	"replace",
	"rotate-this",
	"dummy",
	"github-actions-workflow-dispatch",
}

// maxRunLen is the longest run of a single repeated character allowed in
// a credential value. xxxxx-style manual redaction fills exceed it; real
// base64 / JWT material does not.
const maxRunLen = 8

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kubeconfig }

func (Scanner) Keywords() []string { return []string{"kind: Config", "kind:Config"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	// Gate: require both kind: Config AND a kubeconfig-consistent apiVersion.
	if !kindRe.Match(data) || !apiVersionRe.Match(data) {
		return nil, nil
	}

	str := string(data)

	// Compute users-block windows once: each window starts at the marker
	// and extends usersVicinity bytes. A credential field is accepted only
	// if its match start falls inside one of these windows.
	type window struct{ start, end int }
	var windows []window
	for _, m := range usersBlockRe.FindAllStringIndex(str, -1) {
		windows = append(windows, window{start: m[0], end: m[0] + usersVicinity})
	}
	if len(windows) == 0 {
		return nil, nil
	}
	inUsersVicinity := func(pos int) bool {
		for _, w := range windows {
			if pos >= w.start && pos <= w.end {
				return true
			}
		}
		return false
	}

	out := make([]detectors.Result, 0, 4)
	seen := map[string]struct{}{}

	emit := func(fieldName, value string) {
		if value == "" {
			return
		}
		key := fieldName + ":" + value
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		extra := map[string]string{"field": fieldName}
		// Best-effort capture of the user-name a few lines above the
		// credential field. We grab the LAST `name:` before the credential.
		if idx := strings.Index(str, value); idx > 0 {
			head := str[:idx]
			if matches := nameRe.FindAllStringSubmatch(head, -1); len(matches) > 0 {
				extra["user_name"] = matches[len(matches)-1][1]
			}
		}
		res := detectors.Result{
			DetectorType: detectors.Kubeconfig,
			Raw:          []byte(value),
			Redacted:     redact(value),
			ExtraData:    extra,
			Severity:     detectors.SeverityCritical,
		}
		if userName, ok := extra["user_name"]; ok {
			res.RawV2 = []byte(userName)
		}
		out = append(out, res)
	}

	// scan applies the vicinity + value-quality guards uniformly. checkToken
	// is true only for the bearer-token field, where placeholder/entropy
	// collisions are realistic; base64 cert/key data always clears entropy
	// and we keep its guard to the vicinity + placeholder checks.
	scan := func(re *regexp.Regexp, fieldName string, checkToken bool) {
		for _, m := range re.FindAllStringSubmatchIndex(str, -1) {
			value := str[m[2]:m[3]]
			if !inUsersVicinity(m[0]) {
				continue
			}
			if isPlaceholder(value) {
				continue
			}
			if checkToken && !detectors.HasMinEntropy(value, minTokenEntropy) {
				continue
			}
			emit(fieldName, value)
		}
	}

	scan(clientCertRe, "client-certificate-data", false)
	scan(clientKeyRe, "client-key-data", false)
	scan(tokenRe, "token", true)

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isPlaceholder reports whether value is an obvious non-credential fill.
func isPlaceholder(value string) bool {
	lower := strings.ToLower(value)
	for _, h := range placeholderHints {
		if strings.Contains(lower, h) {
			return true
		}
	}
	// xxxxx-style fills: any single character repeated maxRunLen+ times.
	run := 0
	var prev byte
	for i := 0; i < len(lower); i++ {
		if i > 0 && lower[i] == prev {
			run++
			if run >= maxRunLen {
				return true
			}
		} else {
			run = 1
		}
		prev = lower[i]
	}
	return false
}

func redact(t string) string {
	if len(t) <= 12 {
		return "..."
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
