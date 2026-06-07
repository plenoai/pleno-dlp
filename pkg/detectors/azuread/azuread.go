// Package azuread detects Azure AD (Entra ID) application client secrets and
// pairs them with the application's client id (UUID) when one is in scope.
//
// # Context-Extraction Verify
//
// Verification was historically infeasible because the Azure AD
// client_credentials grant requires the full triple (tenant_id + client_id +
// client_secret) and the tenant_id is neither embedded in the secret nor
// captured by the secret regex.
//
// This detector now uses context extraction: while the tenant_id is not in the
// matched secret itself, it IS often present in the same chunk (config file,
// .env file, YAML, etc.). We scan the chunk data for tenant-related patterns
// (AZURE_TENANT_ID, tenant_id, directory_id, etc.) near the secret match using
// the contextextract package's FindNearbyUUID helper.
//
// When both client_id AND tenant_id are found in context, verification fires
// an OAuth2 client_credentials grant against:
//
//	POST https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token
//
// A 200 with access_token confirms the credential triple is live.
// 401/400 with invalid_client means the secret is invalid.
// When tenant_id is NOT found in context, verification is skipped
// (ExtraData["verify_skip_reason"] = "tenant_id_not_in_context").
//
// The Verify(ctx, secret) method accepts the packed format
// "tenant_id:client_id:client_secret" for callers that already have all three
// components.
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/detectors/contextextract"
)

// minSecretEntropy is the bits/char floor for the matched token. 3.5 is the
// documented base64url/alnum floor (alphabet ~62-64 → ceiling ≈ 6.0); a real
// minted secret sits well above 5.0, low-entropy fillers fall below.
const minSecretEntropy = 3.5

// maxSeparators caps internal `.`/`_`/`-` characters in the trailing run. Real
// minted secrets carry ~0; hyphen-delimited slugs carry several. Two is a safe
// ceiling that still tolerates the rare `.`/`-` Microsoft emits.
const maxSeparators = 2

// verifyTimeout caps the HTTP round-trip for the OAuth2 client_credentials
// grant during verification.
const verifyTimeout = 5 * time.Second

// tenantKeyNames are keys tried in key=value / "key":"value" patterns by
// FindNearbyKeyValue. Each is tried in order; the first hit wins.
var tenantKeyNames = []string{
	"AZURE_TENANT_ID", "azure_tenant_id",
	"tenant_id", "tenantId", "tenantid",
	"directory_id", "directoryId", "directoryid",
}

// tenantUUIDKeywords are the case-insensitive labels that contextextract's
// FindNearbyUUID scans for when locating a tenant_id UUID near the secret
// match. Used as fallback when key-value extraction fails.
var tenantUUIDKeywords = []string{
	"tenant", "tenant_id", "tenantid",
	"directory", "directoryid", "azure_tenant",
}

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

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
			Severity:     detectors.SeverityCritical,
		}

		app, hasApp := nearestAppID(h[2], data, apps)
		if hasApp {
			res.RawV2 = []byte(app)
			res.ExtraData = map[string]string{"client_id": app}
		}

		// Context-extract: search for a tenant_id in the chunk data.
		// Strategy 1: key-value extraction (AZURE_TENANT_ID=xxx, "tenant_id": "xxx").
		tenantID, hasTenant := extractTenantID(data, h[2], h[3], app)
		if hasTenant {
			if res.ExtraData == nil {
				res.ExtraData = map[string]string{}
			}
			res.ExtraData["tenant_id"] = tenantID
		}

		// Verify when requested and the full triple is available.
		if verify && hasApp && hasTenant {
			verified, err := verifyOAuth2(ctx, tenantID, app, token)
			res.Verified = verified
			res.VerificationErr = err
		} else if verify && hasApp && !hasTenant {
			// Cannot verify without tenant_id — record why.
			if res.ExtraData == nil {
				res.ExtraData = map[string]string{}
			}
			res.ExtraData["verify_skip_reason"] = "tenant_id_not_in_context"
		}

		out = append(out, res)
	}
	return out, nil
}

// Verify implements detectors.Verifier. The secret must be in packed format
// "tenant_id:client_id:client_secret" because verification requires all three
// components.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("azuread.Verify: expected packed format tenant_id:client_id:client_secret, got %d parts", len(parts))
	}
	return verifyOAuth2(ctx, parts[0], parts[1], parts[2])
}

// verifyOAuth2 performs the client_credentials grant against Azure AD.
// Returns (true, nil) when the token endpoint returns an access_token (the
// credential triple is live). Returns (false, nil) for definitive rejections
// (invalid_client). Returns (false, err) for transient / ambiguous errors.
func verifyOAuth2(ctx context.Context, tenantID, clientID, clientSecret string) (bool, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
	}

	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return false, nil
	}

	if resp.StatusCode == http.StatusOK {
		var tokenResp struct {
			AccessToken string `json:"access_token"`
		}
		if json.Unmarshal(body, &tokenResp) == nil && tokenResp.AccessToken != "" {
			return true, nil
		}
	}

	// 400/401 with invalid_client is a definitive rejection.
	if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusUnauthorized {
		if strings.Contains(string(body), "invalid_client") {
			return false, nil
		}
	}

	// Other status codes are ambiguous — do not claim verified or unverified.
	return false, nil
}

// uuidRe validates that a string is a standard 8-4-4-4-12 hex UUID.
var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// extractTenantID attempts to locate the Azure tenant_id in the chunk data.
// It first tries direct key-value extraction (AZURE_TENANT_ID=xxx,
// "tenant_id": "xxx"), then falls back to UUID proximity search. The
// clientID parameter is used to exclude the already-identified client_id UUID
// from being misidentified as the tenant_id.
func extractTenantID(data []byte, anchorStart, anchorEnd int, clientID string) (string, bool) {
	// Strategy 1: key-value extraction — most reliable because it directly
	// associates the key name with the value.
	for _, key := range tenantKeyNames {
		if val, ok := contextextract.FindNearbyKeyValue(data, key, 512); ok {
			// Validate that the extracted value looks like a UUID.
			if uuidRe.MatchString(val) && val != clientID {
				return val, true
			}
		}
	}

	// Strategy 2: UUID proximity search near tenant keywords, excluding the
	// client_id UUID.
	if tid, ok := contextextract.FindNearbyUUID(
		data, anchorStart, anchorEnd, tenantUUIDKeywords, 512,
	); ok && tid != clientID {
		return tid, true
	}

	return "", false
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
