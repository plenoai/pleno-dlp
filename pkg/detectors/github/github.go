package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.github.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

const (
	EnvClientID     = "PLENO_DLP_REVOKE_GITHUB_CLIENT_ID"
	EnvClientSecret = "PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET"
	EnvRevokeMode   = "PLENO_DLP_REVOKE_GITHUB_MODE"

	RevokeModeCredentials = "credentials"
	RevokeModeOAuthApp    = "oauth-app"
)

var privilegedScopes = map[string]bool{
	"repo":             true,
	"delete_repo":      true,
	"admin:org":        true,
	"admin:enterprise": true,
	"admin:repo_hook":  true,
	"admin:org_hook":   true,
	"write:packages":   true,
	"workflow":         true,
	"site_admin":       true,
}

var (
	revokeCredsMu sync.RWMutex
	revokeCreds   struct {
		clientID     string
		clientSecret string
		mode         string
	}
)

func SetRevokeCredentials(clientID, clientSecret string) {
	revokeCredsMu.Lock()
	revokeCreds.clientID = clientID
	revokeCreds.clientSecret = clientSecret
	revokeCredsMu.Unlock()
}

func SetRevokeMode(mode string) {
	revokeCredsMu.Lock()
	revokeCreds.mode = mode
	revokeCredsMu.Unlock()
}

func loadRevokeCreds() (clientID, clientSecret string) {
	revokeCredsMu.RLock()
	clientID = revokeCreds.clientID
	clientSecret = revokeCreds.clientSecret
	revokeCredsMu.RUnlock()
	if clientID == "" {
		clientID = os.Getenv(EnvClientID)
	}
	if clientSecret == "" {
		clientSecret = os.Getenv(EnvClientSecret)
	}
	return clientID, clientSecret
}

func loadRevokeMode(clientID, clientSecret string) string {
	revokeCredsMu.RLock()
	mode := revokeCreds.mode
	revokeCredsMu.RUnlock()
	if mode == "" {
		mode = os.Getenv(EnvRevokeMode)
	}
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "", "auto":
		if clientID != "" || clientSecret != "" {
			return RevokeModeOAuthApp
		}
		return RevokeModeCredentials
	case RevokeModeCredentials, "credential", "pat":
		return RevokeModeCredentials
	case RevokeModeOAuthApp, "oauth", "application":
		return RevokeModeOAuthApp
	default:
		return mode
	}
}

var (
	classicRe = regexp.MustCompile(`\b(ghp_[A-Za-z0-9]{36})\b`)
	fineRe    = regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitHub }

func (Scanner) Keywords() []string { return []string{"ghp_", "github_pat_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := classicRe.FindAll(data, -1)
	matches = append(matches, fineRe.FindAll(data, -1)...)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		extra := map[string]string{
			"github_token_type": tokenType(token),
		}
		res := detectors.Result{
			DetectorType: detectors.GitHub,
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
	verified, _, err := verifyWithMetadata(ctx, secret)
	return verified, err
}

func verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		meta := buildMetadata(resp.Header, body)
		return true, meta, nil
	case http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}
}

func buildMetadata(h http.Header, body []byte) map[string]string {
	meta := map[string]string{}
	if scopes := strings.TrimSpace(h.Get("X-OAuth-Scopes")); scopes != "" {
		// Normalise whitespace around the comma-delimited list.
		clean := strings.Join(splitAndTrim(scopes, ","), ",")
		meta["github_scopes"] = clean
		if hasPrivilegedScope(clean) {
			meta["github_privileged"] = "true"
		}
	}
	if exp := strings.TrimSpace(h.Get("Github-Authentication-Token-Expiration")); exp != "" {
		meta["github_token_expiration"] = exp
	}
	var user struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
		Type  string `json:"type"`
	}
	if json.Unmarshal(body, &user) == nil {
		if user.Login != "" {
			meta["github_login"] = user.Login
		}
		if user.ID > 0 {
			meta["github_user_id"] = strconv.FormatInt(user.ID, 10)
		}
		if user.Type != "" {
			meta["github_account_type"] = user.Type
		}
	}
	return meta
}

// hasPrivilegedScope returns true if any token in the comma-delimited
// scopes list is in privilegedScopes. Sub-scopes (`admin:org` covers
// `read:org` and `write:org`) are matched by exact-token lookup; the
// table is curated so the broadest scope is always present.
func hasPrivilegedScope(scopes string) bool {
	for _, s := range splitAndTrim(scopes, ",") {
		if privilegedScopes[s] {
			return true
		}
	}
	return false
}

// tokenType maps a token prefix to its semantic class. The prefixes are
// stable per https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/.
//
//   - ghp_           classic Personal Access Token
//   - github_pat_    fine-grained PAT (resource-scoped)
//   - gho_           OAuth access token
//   - ghu_           user-to-server token (GitHub App acting as user)
//   - ghs_           server-to-server token (GitHub App installation)
//   - ghr_           refresh token
//
// The detector only matches ghp_ and github_pat_ in regex; the other
// prefixes are surfaced if a future regex expansion picks them up,
// which keeps tokenType useful as a forward-looking helper.
func tokenType(token string) string {
	switch {
	case strings.HasPrefix(token, "github_pat_"):
		return "fine-grained"
	case strings.HasPrefix(token, "ghp_"):
		return "classic"
	case strings.HasPrefix(token, "gho_"):
		return "oauth"
	case strings.HasPrefix(token, "ghu_"):
		return "user-to-server"
	case strings.HasPrefix(token, "ghs_"):
		return "server-to-server"
	case strings.HasPrefix(token, "ghr_"):
		return "refresh"
	default:
		return "unknown"
	}
}

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
		return detectors.RevokeResult{}, errors.New("github: revoke: empty secret")
	}
	clientID, clientSecret := loadRevokeCreds()
	mode := loadRevokeMode(clientID, clientSecret)
	switch mode {
	case RevokeModeCredentials:
		return revokeCredential(ctx, secret)
	case RevokeModeOAuthApp:
		return revokeOAuthApp(ctx, secret, clientID, clientSecret)
	default:
		return detectors.RevokeResult{}, fmt.Errorf("github: revoke: unknown mode %q (valid: auto, %s, %s)", mode, RevokeModeCredentials, RevokeModeOAuthApp)
	}
}

func revokeCredential(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	body, err := json.Marshal(map[string][]string{"credentials": []string{secret}})
	if err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("github: credentials revoke: encode body: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/credentials/revoke", bytes.NewReader(body))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2026-03-10")

	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	now := time.Now().UTC()
	switch resp.StatusCode {
	case http.StatusAccepted:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: "github-credentials-revoke"}, nil
	case http.StatusUnprocessableEntity:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{Revoked: false, ProviderID: "github-credentials-revoke", Err: fmt.Errorf("github: credentials revoke validation failed or endpoint throttled (HTTP 422): %s", strings.TrimSpace(string(snippet)))}, nil
	case http.StatusForbidden:
		return detectors.RevokeResult{}, errors.New("github: credentials revoke rejected (HTTP 403); this endpoint must be called without Authorization")
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("github: credentials revoke rate-limited (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("github: credentials revoke unexpected status %s: %s", resp.Status, string(snippet))
	}
}

func revokeOAuthApp(ctx context.Context, secret, clientID, clientSecret string) (detectors.RevokeResult, error) {
	if clientID == "" || clientSecret == "" {
		return detectors.RevokeResult{}, fmt.Errorf(
			"github revoke requires %s + %s (env or --client-id / --client-secret)",
			EnvClientID, EnvClientSecret,
		)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	body, err := json.Marshal(map[string]string{"access_token": secret})
	if err != nil {
		return detectors.RevokeResult{}, fmt.Errorf("github: revoke: encode body: %w", err)
	}
	url := apiBase + "/applications/" + clientID + "/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.RevokeResult{}, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	now := time.Now().UTC()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: clientID}, nil
	case http.StatusNotFound:
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: clientID, Err: errors.New("github: token already revoked or never existed")}, nil
	case http.StatusUnprocessableEntity:
		return detectors.RevokeResult{Revoked: false, ProviderID: clientID, Err: errors.New("github: token is not owned by the configured OAuth app (HTTP 422)")}, nil
	case http.StatusUnauthorized:
		return detectors.RevokeResult{}, fmt.Errorf("github: revoke: OAuth app credentials rejected (HTTP 401) — check %s / %s", EnvClientID, EnvClientSecret)
	case http.StatusTooManyRequests:
		return detectors.RevokeResult{}, errors.New("github: revoke: rate-limited (HTTP 429)")
	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return detectors.RevokeResult{}, fmt.Errorf("github: revoke: unexpected status %s: %s", resp.Status, string(snippet))
	}
}

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
