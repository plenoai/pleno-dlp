// Package azuread detects Azure AD (Entra ID) application client secrets and
// pairs them with the application's client id (UUID) when one is in scope.
//
// Verify is intentionally NOT implemented — this detector is unverified-by-design
// (class b), not "verifiable but not yet wired" (class c). The distinction is
// load-bearing: a class-c claim implies a working verify path exists upstream,
// and for Azure AD client_credentials that claim would be false.
//
// Why verification is infeasible, not merely unimplemented:
//   - The matched Raw secret is NOT self-authenticating. An Azure AD client
//     secret is meaningless without its client_id and unaddressable without the
//     directory tenant. The client_credentials grant requires the full TRIPLE
//     (tenant + client_id + client_secret).
//   - The tenant path segment is MANDATORY in the token URL
//     (https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token); there is
//     no root /oauth2/v2.0/token endpoint. The tenant is opaque — it is not
//     embedded in the secret and is not captured by this detector at all. The
//     /common and /organizations aliases are rejected for the client_credentials
//     grant (AADSTS9002313 / AADSTS500011) regardless of secret validity, so
//     they cannot discriminate a valid secret from an invalid one.
//   - client_id is captured only opportunistically as RawV2 via a nearest-UUID
//     heuristic that may grab an unrelated UUID (tenant id, object id,
//     correlation id, a different app's id). A wrong/missing client_id returns
//     AADSTS700016 (app not found), indistinguishable from an invalid-secret
//     response. A wrong endpoint or missing tenant can only ever yield a hard
//     error, never a true positive.
//
// Therefore any probe would, at best, return an ambiguous error and never a
// confirmed positive. We surface the leak as unverified-by-design and grade it
// SeverityCritical to force rotation — a leaked client secret grants the app's
// full configured scope.
//
// FALSE-POSITIVE CONTROLS (primary first):
//  1. Mandatory tilde anchor — newly minted secrets always contain `~`, the
//     marker that disambiguates them from generic 40-char tokens.
//  2. 256-byte contextKeyword vicinity check + keyword prefilter — the token
//     must sit near an Azure-context word in the chunk.
//  3. Shannon entropy >= 3.5 bits/char — rejects low-entropy template fillers
//     (e.g. `PLACEHOLDER~AAAA…`).
//  4. Trailing run must contain BOTH an alpha and a digit — rejects mono-class
//     lookalikes (all-letters / all-dashes fillers).
//  5. Separator cap — at most maxSeparators of `.`/`_`/`-` in the trailing run.
//     Azure-minted secrets are dense base64url-ish runs that almost never use
//     internal word separators; hyphenated human-readable slugs that happen to
//     carry a tilde near the word "azure" (e.g. ~azureuser-build-artifacts-…,
//     ABC~feature-flag-rollout-…) are mostly separators and are rejected here.
//
// The client secret format Microsoft mints today is documented as ~40 chars in
// the alphabet [A-Za-z0-9~._-] with at least one tilde.
package azuread

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// minSecretEntropy is the bits/char floor for the matched token. 3.5 is the
// documented base64url/alnum floor (alphabet ~62-64 → ceiling ≈ 6.0); a real
// minted secret sits well above 5.0, low-entropy fillers fall below.
const minSecretEntropy = 3.5

// maxSeparators caps internal `.`/`_`/`-` characters in the trailing run. Real
// minted secrets carry ~0; hyphen-delimited slugs carry several. Two is a safe
// ceiling that still tolerates the rare `.`/`-` Microsoft emits.
const maxSeparators = 2

// Client secret: 30+ char run from the Azure secret alphabet that contains at
// least one tilde. The tilde anchor is what keeps this regex from matching
// every random 40-char base64 string. Shape-level filler exclusion (mono-class
// runs, slug-like separator density, low entropy) is enforced in plausibleSecret
// rather than in the regex, where it would be unreadable and hard to test.
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
		// Shape gate: reject low-entropy fillers, mono-class lookalikes, and
		// hyphenated human-readable slugs that merely sit near an azure keyword.
		if !plausibleSecret(token) {
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

// plausibleSecret applies the shape-level FP controls (3,4,5 in the package
// doc). The tilde anchor and keyword vicinity are enforced before this is
// called; this rejects the residual low-entropy / mono-class / slug lookalikes
// that pass the tilde+vicinity gate.
func plausibleSecret(token string) bool {
	// We evaluate the trailing run AFTER the last tilde — that is the random
	// body Microsoft mints; the prefix before the tilde is structural.
	body := token
	if i := strings.LastIndexByte(token, '~'); i >= 0 && i+1 < len(token) {
		body = token[i+1:]
	}

	var hasAlpha, hasDigit, separators int
	for j := 0; j < len(body); j++ {
		c := body[j]
		switch {
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			hasAlpha++
		case c >= '0' && c <= '9':
			hasDigit++
		case c == '.' || c == '_' || c == '-':
			separators++
		}
	}
	// Mono-class exclusion: require a mix beyond a single repeated class.
	if hasAlpha == 0 || hasDigit == 0 {
		return false
	}
	// Slug exclusion: hyphen/underscore/dot density betrays human-readable text.
	if separators > maxSeparators {
		return false
	}
	// Entropy floor: reject template fillers that are alpha+digit but low-info.
	if !detectors.HasMinEntropy(token, minSecretEntropy) {
		return false
	}
	return true
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
