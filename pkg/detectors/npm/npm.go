// Package npm detects npm automation/granular tokens (npm_…) and verifies
// them against registry.npmjs.org/-/whoami. On a verified hit the detector
// also queries /-/npm/v1/user and stamps ExtraData with the npm identity
// and — critically — the publish-time TFA mode. A leaked npm token whose
// owner does NOT enforce TFA-on-write is a direct supply-chain compromise
// surface; a token whose owner enforces "auth-and-writes" still requires an
// OTP to publish. Driftwood pattern: triagers shouldn't have to issue extra
// API calls to learn which one they're staring at.
package npm

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://registry.npmjs.org"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// npm tokens: npm_ + 36 base62 chars.
var tokenRe = regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.NPM }

func (Scanner) Keywords() []string { return []string{"npm_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.NPM,
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := s.verifyWithMetadata(ctx, secret)
	return v, err
}

func (Scanner) verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/-/whoami", nil)
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
		// fall through to decode
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}

	meta := map[string]string{}
	var who struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&who); err == nil && who.Username != "" {
		meta["npm_username"] = who.Username
	}

	// Best-effort enrichment: /-/npm/v1/user returns the publisher profile
	// including the TFA mode, which determines whether a stolen token alone
	// can publish or whether an additional OTP is required.
	if profile := fetchUserProfile(ctx, secret); profile != nil {
		if profile.Email != "" {
			meta["npm_email"] = profile.Email
		}
		if profile.Name != "" {
			meta["npm_full_name"] = profile.Name
		}
		switch tfaMode(profile.TFA) {
		case "auth-and-writes":
			// Strongest mode: every publish requires a fresh OTP. The token
			// alone is not sufficient for supply-chain mutation.
			meta["npm_tfa_mode"] = "auth-and-writes"
			meta["npm_publish_requires_tfa"] = "true"
		case "auth-only":
			// 2FA gates login but not publish. Token alone CAN publish.
			meta["npm_tfa_mode"] = "auth-only"
			meta["npm_high_risk"] = "true"
		case "disabled":
			// No TFA at all. Worst case for a leaked publish-capable token.
			meta["npm_tfa_mode"] = "disabled"
			meta["npm_high_risk"] = "true"
		}
	}
	return true, meta, nil
}

// npm returns `"tfa": false` when TFA is disabled and an object
// `{"mode": "auth-only" | "auth-and-writes"}` otherwise. We accept both
// shapes via RawMessage so the decoder doesn't blow up on the bool form.
type npmUserProfile struct {
	Email string          `json:"email"`
	Name  string          `json:"name"`
	TFA   json.RawMessage `json:"tfa"`
}

func tfaMode(raw json.RawMessage) string {
	trimmed := string(raw)
	if trimmed == "" || trimmed == "null" || trimmed == "false" {
		return "disabled"
	}
	var obj struct {
		Mode string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return "disabled"
	}
	if obj.Mode == "" {
		return "disabled"
	}
	return obj.Mode
}

func fetchUserProfile(ctx context.Context, secret string) *npmUserProfile {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/-/npm/v1/user", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var p npmUserProfile
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		return nil
	}
	return &p
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
