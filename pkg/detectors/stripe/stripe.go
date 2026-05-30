// Package stripe detects Stripe live/test secret keys (sk_live_, sk_test_,
// rk_live_) and verifies them via /v1/account.
//
// Verify also enriches the finding with blast-radius metadata when the
// upstream call succeeds (driftwood-style "what does this credential
// actually unlock"):
//
//   - stripe_key_mode         live | test | restricted-live | restricted-test
//   - stripe_account_id       acct_… returned by /v1/account
//   - stripe_business_name    display name (when set)
//   - stripe_country          ISO-3166-1 alpha-2 (US, JP, …)
//   - stripe_default_currency lowercase ISO-4217 (usd, jpy, …)
//   - stripe_livemode         "true" when /v1/account.livemode=true.
//     Distinguishes a sk_live_ key minted in the
//     live dashboard from a sk_live_-shaped fake.
//   - stripe_charges_enabled  "true" when the account can accept
//     charges. live + charges_enabled is the
//     "real money flowing" signal.
//   - stripe_payouts_enabled  "true" when the account can issue payouts
//   - stripe_high_value       "true" when live + charges_enabled +
//     payouts_enabled. Triage flag for "this
//     leak can move money out of the account."
//
// Revoke (issue #73) only supports Stripe restricted keys (rk_test_ /
// rk_live_) via POST /v1/api_keys/{key}/revoke with the key acting as
// its own bearer (self-revoke). The standard sk_live_ / sk_test_ secret
// keys do NOT expose a programmatic revoke endpoint — they must be
// rotated via the Stripe dashboard. Revoke surfaces sk_-prefixed input
// as an explicit unsupported error so callers don't silently believe
// the secret is dead. HTTP 404 against the self-revoke path is treated
// as idempotent (already revoked / never existed).
package stripe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.stripe.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// sk_live_, sk_test_, rk_live_ all share the same suffix shape: 20–247 base62
// chars. trufflehog uses the same canonical pattern.
var keyRe = regexp.MustCompile(`\b((?:sk_live_|sk_test_|rk_live_)[A-Za-z0-9]{20,247})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Stripe }

func (Scanner) Keywords() []string { return []string{"sk_live_", "sk_test_", "rk_live_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		extra := map[string]string{
			"stripe_key_mode": keyMode(token),
		}
		res := detectors.Result{
			DetectorType: detectors.Stripe,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			verified, meta, err := verifyWithMetadata(ctx, token)
			res.Verified = verified
			res.VerificationErr = err
			for k, v := range meta {
				extra[k] = v
			}
		}
		out = append(out, res)
	}
	return out, nil
}

// Verify implements detectors.Verifier. The richer metadata-bearing
// path lives in verifyWithMetadata so FromData can fold it into
// ExtraData without changing the engine contract.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := verifyWithMetadata(ctx, secret)
	return v, err
}

// verifyWithMetadata calls /v1/account, the canonical "what is this
// key" endpoint. The body returns the full account profile we need
// for blast-radius enrichment; on 401/403 we fall back to the
// legacy /v1/charges check so a key that is restricted away from
// /v1/account still verifies (e.g. some rk_*_ keys without
// account.read scope).
func verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/account", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		return true, accountMetadata(body), nil
	case http.StatusForbidden:
		// Restricted key without `account` resource. The key is real (a
		// 401 would mean it's not), but we cannot enrich. Fall back to
		// /v1/charges to confirm validity, then return verified=true
		// without metadata.
		return verifyChargesFallback(ctx, secret)
	case http.StatusUnauthorized, http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}
}

// verifyChargesFallback handles the restricted-key case: keys that
// authenticate but lack permission to read /v1/account. Verifies via
// /v1/charges (the original endpoint) and returns verified=true with
// no metadata so the caller still gets the live/dead signal.
func verifyChargesFallback(ctx context.Context, secret string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/charges?limit=1", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil, nil
}

// accountMetadata extracts the blast-radius surface from /v1/account.
// Empty fields are omitted so the ExtraData map stays compact.
func accountMetadata(body []byte) map[string]string {
	var acct struct {
		ID              string `json:"id"`
		Country         string `json:"country"`
		DefaultCurrency string `json:"default_currency"`
		DisplayName     string `json:"display_name"`
		Email           string `json:"email"`
		Livemode        bool   `json:"livemode"`
		ChargesEnabled  bool   `json:"charges_enabled"`
		PayoutsEnabled  bool   `json:"payouts_enabled"`
		BusinessProfile struct {
			Name string `json:"name"`
		} `json:"business_profile"`
	}
	if json.Unmarshal(body, &acct) != nil {
		return nil
	}
	meta := map[string]string{}
	if acct.ID != "" {
		meta["stripe_account_id"] = acct.ID
	}
	if name := firstNonEmpty(acct.BusinessProfile.Name, acct.DisplayName); name != "" {
		meta["stripe_business_name"] = name
	}
	if acct.Country != "" {
		meta["stripe_country"] = acct.Country
	}
	if acct.DefaultCurrency != "" {
		meta["stripe_default_currency"] = acct.DefaultCurrency
	}
	if acct.Livemode {
		meta["stripe_livemode"] = "true"
	}
	if acct.ChargesEnabled {
		meta["stripe_charges_enabled"] = "true"
	}
	if acct.PayoutsEnabled {
		meta["stripe_payouts_enabled"] = "true"
	}
	if acct.Livemode && acct.ChargesEnabled && acct.PayoutsEnabled {
		// "Real money can move out of this account using only this key."
		// That is the highest-impact tier of Stripe leak.
		meta["stripe_high_value"] = "true"
	}
	return meta
}

// keyMode maps a key prefix to its semantic class. Available from regex
// alone, no network call; surfaced even for unverified findings so
// triage can sort by impact on offline scans.
func keyMode(token string) string {
	switch {
	case strings.HasPrefix(token, "rk_live_"):
		return "restricted-live"
	case strings.HasPrefix(token, "rk_test_"):
		return "restricted-test"
	case strings.HasPrefix(token, "sk_live_"):
		return "live"
	case strings.HasPrefix(token, "sk_test_"):
		return "test"
	default:
		return "unknown"
	}
}

// firstNonEmpty returns the first non-empty string from its arguments.
// Used to coalesce the two "name" surfaces /v1/account exposes
// (business_profile.name, display_name) without nested if-blocks.
func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// redact preserves the recognizable provider prefix plus four chars so
// operators can correlate findings without seeing the live secret.
func redact(t string) string {
	for _, p := range []string{"sk_live_", "sk_test_", "rk_live_"} {
		if len(t) > len(p)+4 && t[:len(p)] == p {
			return t[:len(p)+4] + "..."
		}
	}
	if len(t) > 8 {
		return t[:8] + "..."
	}
	return t + "..."
}

// Revoke implements detectors.Revoker for Stripe restricted keys.
//
// Stripe exposes self-revocation only for restricted keys (rk_test_ /
// rk_live_) via POST /v1/api_keys/{key}/revoke. The key authenticates
// the request as its own Bearer token and identifies itself in the
// path. Standard secret keys (sk_live_ / sk_test_) have no programmatic
// revoke surface — those rotate via the dashboard, so we reject them
// with an explicit error rather than pretending the call could succeed.
//
// Status handling:
//   - 200 + {"revoked": true}  -> Revoked = true.
//   - 200 + {"revoked": false} -> Revoked = false; non-fatal err carries
//     the response snippet so the caller can log why Stripe declined.
//   - 404 Not Found            -> idempotent: token already revoked or
//     never existed. Revoked = true with a non-fatal note.
//   - 401 Unauthorized         -> hard error (key invalid).
//   - 429 Too Many Requests    -> hard error; we do not retry, matching
//     the Verify policy so a rate-limited provider can't stall a scan.
//   - other 4xx / 5xx          -> hard error with status + body snippet.
//
// ProviderID echoes the key's prefix-bounded id (the segment after
// `rk_(test|live)_`) so audit logs can cross-reference revocations
// without recording the full secret.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("stripe: revoke: empty secret")
	}
	if !strings.HasPrefix(secret, "rk_test_") && !strings.HasPrefix(secret, "rk_live_") {
		return detectors.RevokeResult{}, errors.New("stripe: revoke: only restricted keys (rk_test_/rk_live_) are supported; sk_ secret keys must be rotated via the dashboard")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	url := apiBase + "/v1/api_keys/" + secret + "/revoke"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	now := time.Now().UTC()
	providerID := stripeProviderID(secret)

	switch resp.StatusCode {
	case http.StatusOK:
		// Read a bounded snippet so we can cheaply detect {"revoked": false}
		// without pulling in encoding/json — the API contract is stable
		// enough that a substring check is sufficient and keeps the
		// dependency surface minimal.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s := string(body)
		if strings.Contains(s, "\"revoked\":false") || strings.Contains(s, "\"revoked\": false") {
			return detectors.RevokeResult{Revoked: false, ProviderID: providerID, Err: fmt.Errorf("stripe: revoke: provider returned revoked=false: %s", s)}, nil
		}
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID}, nil
	case http.StatusNotFound:
		// Idempotent: key already revoked or never existed.
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID, Err: errors.New("stripe: revoke: already revoked or never existed (HTTP 404)")}, nil
	case http.StatusUnauthorized:
		return detectors.RevokeResult{}, errors.New("stripe: revoke: unauthorized (HTTP 401) — key invalid or already revoked at the auth layer")
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("stripe: revoke: rate-limited (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("stripe: revoke: unexpected status %s: %s", resp.Status, string(snippet))
	}
}

// stripeProviderID extracts the key's identifier segment so audit logs
// can correlate without storing the full secret. For `rk_test_xyz` we
// return `rk_test_xyz` truncated to a prefix-bounded form — Stripe does
// not expose a separate stable id for restricted keys outside the key
// itself, so we return the key's recognisable prefix and short tail.
func stripeProviderID(secret string) string {
	for _, p := range []string{"rk_live_", "rk_test_"} {
		if strings.HasPrefix(secret, p) {
			tailStart := len(p)
			tailEnd := tailStart + 4
			if tailEnd > len(secret) {
				tailEnd = len(secret)
			}
			return p + secret[tailStart:tailEnd]
		}
	}
	return ""
}

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
