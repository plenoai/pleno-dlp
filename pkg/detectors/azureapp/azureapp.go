// Package azureapp detects legacy Azure AD application secrets that the
// `azuread` package's tilde-anchored regex misses.
//
// Azure AD has minted multiple secret formats over the years:
//   - The current format (handled by pkg/detectors/azuread) requires at
//     least one `~` and is 30-40 chars from the alphabet [A-Za-z0-9~._-].
//   - The legacy v1 format omits the tilde — `xx.xx_xxx-xxx…` style — and
//     is still in active use for app registrations created before 2021.
//
// We require strict co-occurrence with both a `client_id` keyword and a
// nearby UUID to keep the false-positive rate manageable: a 30+ char run
// from [A-Za-z0-9._-] is otherwise far too generic. Verify is intentionally
// not implemented — like azuread, the tenant is rarely embedded in the
// source chunk so any probe would target the wrong directory. Surfaces
// unverified-by-design at SeverityCritical because the secret grants the
// app's full configured scope.
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

// Co-occurrence keywords are deliberately tight — the regex shape is so
// generic that a loose gate would fire on every base64 chunk in the
// codebase. Both client_id AND a UUID must be near the candidate.
var contextKeywords = []string{"client_id", "appid", "azure", "azuread", "entra"}

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
		if !nearKeyword(lower, h[2], h[3]) {
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

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
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
