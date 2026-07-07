// Package slack detects Slack bot tokens and incoming webhook URLs. Bot tokens
// also support revocation.
package slack

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

var apiBase = "https://slack.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// xoxb-<workspace_id>-<bot_id>-<secret>.
var tokenRe = regexp.MustCompile(`\b(xoxb-\d+-\d+-[A-Za-z0-9]{24,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SlackBotToken }

func (Scanner) Keywords() []string { return []string{"xoxb-"} }

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
			DetectorType: detectors.SlackBotToken,
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

// privilegedScopes mark high-blast-radius Slack OAuth scopes.
var privilegedScopes = map[string]bool{
	"admin":                     true,
	"admin.users:write":         true,
	"admin.conversations:write": true,
	"admin.teams:write":         true,
	"chat:write.public":         true,
	"users:read.email":          true,
	"files:write":               true,
}

// verifyWithMetadata posts to /api/auth.test and decodes identity metadata.
func verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/auth.test", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil, nil
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var auth struct {
		OK           bool   `json:"ok"`
		URL          string `json:"url"`
		Team         string `json:"team"`
		User         string `json:"user"`
		TeamID       string `json:"team_id"`
		UserID       string `json:"user_id"`
		BotID        string `json:"bot_id"`
		EnterpriseID string `json:"enterprise_id"`
		IsEnterprise bool   `json:"is_enterprise_install"`
	}
	if err := json.Unmarshal(body, &auth); err != nil {
		return false, nil, nil
	}
	if !auth.OK {
		return false, nil, nil
	}
	meta := buildAuthMetadata(resp.Header, &auth)
	return true, meta, nil
}

// buildAuthMetadata assembles ExtraData from a successful auth.test response.
func buildAuthMetadata(h http.Header, auth *struct {
	OK           bool   `json:"ok"`
	URL          string `json:"url"`
	Team         string `json:"team"`
	User         string `json:"user"`
	TeamID       string `json:"team_id"`
	UserID       string `json:"user_id"`
	BotID        string `json:"bot_id"`
	EnterpriseID string `json:"enterprise_id"`
	IsEnterprise bool   `json:"is_enterprise_install"`
}) map[string]string {
	meta := map[string]string{}
	if auth.TeamID != "" {
		meta["slack_team_id"] = auth.TeamID
	}
	if auth.Team != "" {
		meta["slack_team_name"] = auth.Team
	}
	if auth.URL != "" {
		meta["slack_team_url"] = auth.URL
	}
	if auth.UserID != "" {
		meta["slack_user_id"] = auth.UserID
	}
	if auth.User != "" {
		meta["slack_user_name"] = auth.User
	}
	if auth.BotID != "" {
		meta["slack_bot_id"] = auth.BotID
	}
	if auth.EnterpriseID != "" {
		meta["slack_enterprise_id"] = auth.EnterpriseID
	}
	if auth.IsEnterprise {
		meta["slack_enterprise_install"] = "true"
	}
	if scopes := strings.TrimSpace(h.Get("X-OAuth-Scopes")); scopes != "" {
		clean := strings.Join(splitAndTrim(scopes, ","), ",")
		meta["slack_scopes"] = clean
		if hasPrivilegedScope(clean) {
			meta["slack_privileged"] = "true"
		}
	}
	return meta
}

func hasPrivilegedScope(scopes string) bool {
	for _, s := range splitAndTrim(scopes, ",") {
		if privilegedScopes[s] {
			return true
		}
	}
	return false
}

// splitAndTrim splits s on sep and trims whitespace from each element,
// dropping empties. Slack returns scopes as "a,b" or "a, b" depending
// on the endpoint and version.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("slack: revoke: empty secret")
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/auth.revoke", nil)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusTooManyRequests {
		return detectors.RevokeResult{}, errors.New("slack: revoke: rate-limited (HTTP 429)")
	}
	if resp.StatusCode >= 500 {
		return detectors.RevokeResult{}, fmt.Errorf("slack: revoke: server error: %s", resp.Status)
	}
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("slack: revoke: unexpected status %s: %s", resp.Status, strings.TrimSpace(string(snippet)))
	}

	var body struct {
		OK      bool   `json:"ok"`
		Revoked bool   `json:"revoked"`
		Error   string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("slack: revoke: decode response: %w", err)
	}

	now := time.Now().UTC()
	if body.OK && body.Revoked {
		return detectors.RevokeResult{Revoked: true, RevokedAt: now}, nil
	}
	if body.OK {
		// ok=true but revoked=false is undocumented; treat as not-revoked
		// with a diagnostic so the caller can investigate.
		return detectors.RevokeResult{Revoked: false, Err: errors.New("slack: revoke: ok=true but revoked=false")}, nil
	}
	switch body.Error {
	case "token_revoked":
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, Err: errors.New("slack: token already revoked")}, nil
	case "invalid_auth", "not_authed":
		// Already-revoked tokens, fakes, and never-valid tokens all
		// surface here. Treat as idempotent success — from the caller's
		// perspective the secret is no longer usable, which is the
		// terminal state Revoke promises.
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, Err: fmt.Errorf("slack: invalid auth (already revoked or fake): %s", body.Error)}, nil
	default:
		msg := body.Error
		if msg == "" {
			msg = "unknown_error"
		}
		return detectors.RevokeResult{Revoked: false, Err: fmt.Errorf("slack: revoke: %s", msg)}, nil
	}
}

func redact(t string) string {
	if len(t) <= 5 {
		return t
	}
	return t[:5] + "..."
}

var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
