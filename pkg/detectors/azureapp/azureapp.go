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
package azureapp

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

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AzureApp }

func (Scanner) Keywords() []string { return []string{"client_id", "azure"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
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
			// configured scope.
			Severity: detectors.SeverityCritical,
		}

		// Context-extract: search for a tenant_id in the chunk data.
		// Strategy 1: key-value extraction (AZURE_TENANT_ID=xxx, "tenant_id": "xxx").
		tenantID, hasTenant := extractTenantID(data, h[2], h[3], app)
		if hasTenant {
			res.ExtraData["tenant_id"] = tenantID
		}

		// Verify when requested and the full triple is available.
		if verify && hasTenant {
			verified, err := verifyOAuth2(ctx, tenantID, app, token)
			res.Verified = verified
			res.VerificationErr = err
		} else if verify && !hasTenant {
			// Cannot verify without tenant_id — record why.
			res.ExtraData["verify_skip_reason"] = "tenant_id_not_in_context"
		}

		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify implements detectors.Verifier. The secret must be in packed format
// "tenant_id:client_id:client_secret" because verification requires all three
// components.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 3)
	if len(parts) != 3 {
		return false, fmt.Errorf("azureapp.Verify: expected packed format tenant_id:client_id:client_secret, got %d parts", len(parts))
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
