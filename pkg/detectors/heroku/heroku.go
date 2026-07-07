// Package heroku detects Heroku API tokens (UUIDs) and verifies them against
// /account, decoding the account to surface blast radius: a token with no 2FA
// is account takeover; a federated/SSO account requires the IdP. UUID alone is
// too generic, so a "heroku" keyword must appear within 256 bytes.
package heroku

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.heroku.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Heroku doesn't require UUID v4, so we accept any hex UUID and lean on the
// keyword gate for precision.
var tokenRe = regexp.MustCompile(`\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)

var contextKeywords = []string{"heroku", "heroku_api_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Heroku }

func (Scanner) Keywords() []string { return []string{"heroku"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.Heroku,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			v, meta, err := s.verifyWithMetadata(ctx, token)
			res.Verified = v
			res.VerificationErr = err
			for k, val := range meta {
				extra[k] = val
			}
		}
		out = append(out, res)
	}
	return out, nil
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := s.verifyWithMetadata(ctx, secret)
	return v, err
}

func (Scanner) verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/account", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	// Heroku rejects requests without the versioned Accept header. Even on
	// auth failure they 406 instead of 401, which would invert our verify
	// signal.
	req.Header.Set("Accept", "application/vnd.heroku+json; version=3")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}

	var body struct {
		ID                      string  `json:"id"`
		Email                   string  `json:"email"`
		Name                    string  `json:"name"`
		TwoFactorAuthentication bool    `json:"two_factor_authentication"`
		SSOTargetURL            *string `json:"sso_target_url"`
		Federated               bool    `json:"federated"`
		Verified                bool    `json:"verified"`
		SuspendedAt             *string `json:"suspended_at"`
	}
	meta := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		if body.ID != "" {
			meta["heroku_user_id"] = body.ID
		}
		if body.Email != "" {
			meta["heroku_email"] = body.Email
		}
		if body.Name != "" {
			meta["heroku_user_name"] = body.Name
		}
		meta["heroku_two_factor"] = strconv.FormatBool(body.TwoFactorAuthentication)
		// Heroku marks an account "federated" when the email domain is
		// managed via SSO; sso_target_url being non-null means the user is
		// forced through an IdP for login.
		if body.Federated || (body.SSOTargetURL != nil && *body.SSOTargetURL != "") {
			meta["heroku_sso"] = "true"
		}
		if body.SuspendedAt != nil && *body.SuspendedAt != "" {
			meta["heroku_account_suspended"] = "true"
		}
		// High risk: token alone is full account access (no 2FA, no SSO
		// gate) and the account is alive (not suspended).
		if !body.TwoFactorAuthentication &&
			!body.Federated &&
			(body.SSOTargetURL == nil || *body.SSOTargetURL == "") &&
			(body.SuspendedAt == nil || *body.SuspendedAt == "") {
			meta["heroku_high_risk"] = "true"
		}
	}
	return true, meta, nil
}

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
