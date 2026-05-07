// Package azuread detects Azure AD (Entra ID) application client secrets and
// pairs them with the application's client id (UUID) when one is in scope.
//
// Verify is intentionally not implemented. Azure AD's token endpoint lives at
// https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token and the tenant
// portion is rarely embedded next to the secret in the source chunk. Without a
// reliable tenant we'd probe the wrong directory on every hit, so we surface
// the leak as unverified-by-design — leaked client secrets grant the app's
// full configured scope, so any unverified hit is graded SeverityCritical to
// force rotation.
//
// The client secret format Microsoft mints today is documented as 40 chars in
// the alphabet [A-Za-z0-9~._-] with at least one tilde — newly generated
// secrets always contain `~`, which is the marker that disambiguates them
// from generic 40-char tokens.
package azuread

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Client secret: 30+ char run from the Azure secret alphabet that contains at
// least one tilde. The tilde anchor is what keeps this regex from matching
// every random 40-char base64 string.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9~._-]{2,}~[A-Za-z0-9~._-]{30,})\b`)

// Application (client) id: lowercase hex UUID.
var appIDRe = regexp.MustCompile(`\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

var contextKeywords = []string{"azure", "azuread", "client_secret", "client_id", "appid", "tenant", "entra"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureAD }

// "~" alone would be far too noisy as a prefilter. We keyword-gate on
// "azure" / "client_secret" — operators who paste a bare secret will be missed,
// but the false-positive cost of a tilde-only prefilter is unacceptable.
func (Scanner) Keywords() []string { return []string{"azure", "client_secret"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	apps := appIDRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Co-occurrence is mandatory — tilde-bearing tokens still appear in
		// kubernetes manifests, jwt signing kids, etc.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.AzureAD,
			Raw:          []byte(token),
			Redacted:     redact(token),
			// Critical because client_secret grants the app's full configured
			// scope. Verified=false because tenant is not extractable.
			Severity: detectors.SeverityCritical,
		}
		if app, ok := nearestAppID(h[2], data, apps); ok {
			res.RawV2 = []byte(app)
			res.ExtraData = map[string]string{"client_id": app}
		}
		out = append(out, res)
	}
	return out, nil
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
