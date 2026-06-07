// Package stripe detects Stripe keys, verifies them, and supports restricted-key revoke.
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

// sk_live_, sk_test_, and rk_live_ share the same suffix shape.
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := verifyWithMetadata(ctx, secret)
	return v, err
}

// verifyWithMetadata calls /v1/account and falls back to /v1/charges for restricted keys.
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
		return verifyChargesFallback(ctx, secret)
	case http.StatusUnauthorized, http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}
}

// verifyChargesFallback handles restricted keys that cannot read /v1/account.
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

// accountMetadata extracts blast-radius fields from /v1/account.
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
		meta["stripe_high_value"] = "true"
	}
	return meta
}

// keyMode maps a key prefix to its semantic class.
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		s := string(body)
		if strings.Contains(s, "\"revoked\":false") || strings.Contains(s, "\"revoked\": false") {
			return detectors.RevokeResult{Revoked: false, ProviderID: providerID, Err: fmt.Errorf("stripe: revoke: provider returned revoked=false: %s", s)}, nil
		}
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: providerID}, nil
	case http.StatusNotFound:
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

// stripeProviderID extracts a prefix-bounded identifier for audit logs.
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
