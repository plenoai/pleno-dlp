// Package azureapp detects legacy Azure AD application secrets that the
// `azuread` package's tilde-anchored regex misses.
//
// Azure AD has minted multiple secret formats over the years:
//   - The current format (handled by pkg/detectors/azuread) requires at
//     least one `~` and is 30-40 chars from the alphabet [A-Za-z0-9~._-].
//   - The legacy v1 format omits the tilde — `xx.xx_xxx-xxx…` style — and
//     is still in active use for app registrations created before 2021.
//
// A 30+ char run from [A-Za-z0-9._-] is far too generic on its own, so we
// stack several gates to keep the false-positive rate manageable:
//   - a nearby client_id UUID (the pairing),
//   - a secret-intent keyword (client_secret/secret/password/pwd) within a
//     tight 64-byte window — co-location with a secret-assignment site is the
//     real signal, not a broad "azure" mention,
//   - a minimum Shannon entropy of 3.5 bits/char,
//   - a minimum 12-char unbroken alnum run (v1 secrets pack alnum densely;
//     kebab/dotted slugs and package paths are chopped into short segments),
//   - negative-lookalike exclusions for SRI/digest prefixes (sha256- etc.),
//     UUIDs, and tilde-bearing shapes (owned by pkg/detectors/azuread).
//
// Verify is intentionally NOT implemented (class=b, unverified-by-design).
// Verifying an Azure AD client credential is a client_credentials OAuth2
// grant against https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
// where {tenant} is MANDATORY and is not derivable: it is distinct from the
// appid, is never in the secret, and is not captured by this detector.
// Microsoft rejects the multi-tenant common/organizations endpoints for
// app-only client_credentials, so there is no fixed or derivable host — an
// apiBase-only probe would no-op on essentially every real hit. Surfaces at
// SeverityCritical because the secret grants the app's full configured scope.
package azureapp

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Legacy v1 secret: 30+ char run with at least one of `.`, `_`, or `-` so
// pure alphanumeric runs (which collide with countless other token shapes)
// are filtered out. We never match a tilde here — those belong to azuread.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9][A-Za-z0-9._-]{28,40}[A-Za-z0-9])\b`)

var appIDRe = regexp.MustCompile(`\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

// Co-occurrence keywords are deliberately tight. The regex shape is so
// generic that the old broad gate (azure / client_id / appid within 256
// bytes) fired on every config block that merely mentioned Azure. The real
// signal is co-location with a *secret-assignment* site, so we now require a
// secret-intent keyword within a small window of the candidate. A nearby
// UUID is still required as the client_id pairing.
var secretKeywords = []string{"client_secret", "clientsecret", "secret", "password", "pwd"}

// minEntropy gates out low-information runs. Legacy Azure v1 secrets are
// high-entropy random strings; FQ symbol slugs and resource-name slugs sit
// well below this floor once their dense alnum content is missing.
const minEntropy = 3.5

// sriPrefixes are Subresource-Integrity / digest prefixes. A candidate that
// begins with one of these is a hash, not a secret.
var sriPrefixes = []string{"sha256-", "sha384-", "sha512-", "md5-"}

// denseRunRe finds the longest unbroken alphanumeric run inside a candidate
// (no `.`, `_`, `-`). Legacy Azure v1 secrets pack alnum densely with only
// sparse separators, so they always contain a long unbroken run. Package
// paths and kebab/resource slugs (`com.microsoft.azure.identity…`,
// `my-azure-app-prod-eastus-2024-deploy01`) are chopped into short segments
// and have no long run.
var denseRunRe = regexp.MustCompile(`[A-Za-z0-9]+`)

// minDenseRun is the shortest unbroken alnum run a real v1 secret must
// contain. Resource-name and FQ-symbol slugs never reach this.
const minDenseRun = 12

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureApp }

func (Scanner) Keywords() []string { return []string{"client_id", "azure"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	apps := appIDRe.FindAllSubmatchIndex(data, -1)
	if len(apps) == 0 {
		// No client_id UUID nearby means the candidate is not a client
		// secret in any usable sense — bail before scanning.
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Skip tokens that contain a tilde — those are the modern azuread
		// shape and are owned by pkg/detectors/azuread.
		if strings.Contains(token, "~") {
			continue
		}
		// Skip tokens that look like UUIDs (those are the client_id
		// itself — we'd otherwise emit it as the secret).
		if isUUIDish(token) {
			continue
		}
		// Skip tokens that are pure dot-separated runs like JWTs or
		// `package.module.Class` symbols — those have no underscores or
		// hyphens that would mark them as Azure secrets.
		if !strings.ContainsAny(token, "_-") {
			continue
		}
		// Negative-lookalike: SRI / digest prefixes are hashes, not secrets.
		if hasSRIPrefix(token) {
			continue
		}
		// Structure check: a real v1 secret packs alnum densely. Slugs and
		// package paths are chopped into short separator-delimited segments
		// with no long unbroken run.
		if longestDenseRun(token) < minDenseRun {
			continue
		}
		// Entropy gate: drop low-information runs (resource-name slugs,
		// FQ symbols) that survive the structure check.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// The decisive signal is co-location with a secret-assignment site:
		// a secret-intent keyword within a small window of the candidate.
		if !nearSecretKeyword(lower, h[2], h[3]) {
			continue
		}
		app, hasApp := nearestAppID(h[2], data, apps)
		if !hasApp {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AzureApp,
			Raw:          []byte(token),
			Redacted:     redact(token),
			RawV2:        []byte(app),
			ExtraData:    map[string]string{"client_id": app},
			// Critical because the secret grants the registered app's full
			// configured scope. Verified=false because the tenant cannot be
			// recovered from the chunk reliably.
			Severity: detectors.SeverityCritical,
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isUUIDish returns true for runs that have UUID-like dash positions.
// Used to avoid surfacing the client_id UUID itself as the secret token.
func isUUIDish(s string) bool {
	if len(s) != 36 {
		return false
	}
	return s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-'
}

func nearestAppID(start int, data []byte, apps [][]int) (string, bool) {
	const maxDistance = 512
	bestDist := maxDistance + 1
	best := ""
	for _, a := range apps {
		s, e := a[2], a[3]
		dist := abs(s - start)
		if dist < bestDist {
			bestDist = dist
			best = string(data[s:e])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func hasSRIPrefix(token string) bool {
	lower := strings.ToLower(token)
	for _, p := range sriPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

func longestDenseRun(token string) int {
	best := 0
	for _, run := range denseRunRe.FindAllString(token, -1) {
		if len(run) > best {
			best = len(run)
		}
	}
	return best
}

// nearSecretKeyword requires a secret-intent keyword within a tight window of
// the candidate — co-location with a secret-assignment site is the real
// signal, far more discriminating than a broad azure/client_id mention.
func nearSecretKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range secretKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
