// Package github detects GitHub Personal Access Tokens (classic and
// fine-grained) and verifies them against api.github.com/user.
//
// Verify also enriches the finding with blast-radius metadata when the
// upstream call succeeds:
//
//   - github_login         the authenticated user's login
//   - github_user_id       the numeric user id
//   - github_token_type    classic | fine-grained | oauth | user-to-server | server-to-server | refresh
//   - github_scopes        the X-OAuth-Scopes header (classic only;
//     fine-grained tokens do not expose granular
//     scope strings via this header — they encode
//     permissions per-resource on the token itself)
//   - github_token_expiration  the GitHub-Authentication-Token-Expiration
//     header value when present (fine-grained PATs
//     and SAML-enforced classic PATs)
//   - github_privileged    "true" when github_scopes contains any of the
//     high-blast-radius scopes (`repo`, `admin:org`,
//     `delete_repo`, `admin:enterprise`,
//     `write:packages`, `workflow`). Severity stays
//     Critical via the verified path; the flag
//     surfaces the WHY for triage.
//
// Inspired by trufflesecurity/driftwood's "what does this credential
// actually unlock" pattern, ported from PrivateKeyPEM CT-log lookup
// (see pkg/detectors/privatekey/blastradius).
//
// Revoke (issue #73) calls DELETE /applications/{client_id}/token on
// api.github.com against an OAuth app's client_id+client_secret,
// per https://docs.github.com/en/rest/apps/oauth-applications. The
// endpoint only works for tokens that the configured OAuth app issued;
// raw user-owned PATs (`ghp_...` not minted by an app) reject with 422
// and surface as Revoked=false with a non-fatal diagnostic in
// RevokeResult.Err. Callers wire the OAuth app's client credentials via
// SetRevokeCredentials (CLI plumbing) or the
// PLENO_DLP_REVOKE_GITHUB_CLIENT_ID / PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET
// env vars; without them, Revoke returns a hard error so a misconfigured
// CI does not silently skip revocation.
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

// apiBase is overridable from tests so verification can hit an httptest server.
var apiBase = "https://api.github.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Env variable names for the OAuth App credential pair Revoke needs.
const (
	EnvClientID     = "PLENO_DLP_REVOKE_GITHUB_CLIENT_ID"
	EnvClientSecret = "PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET"
)

// privilegedScopes is the subset of OAuth-app scopes whose grant amounts
// to "this token can substantially damage the org" — repo write, admin
// surfaces, package publishing, workflow editing, repo deletion. Used to
// flip the github_privileged ExtraData flag so triage can sort verified
// findings by impact even within the Critical bucket.
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
	}
)

// SetRevokeCredentials wires the OAuth app credentials Revoke uses.
func SetRevokeCredentials(clientID, clientSecret string) {
	revokeCredsMu.Lock()
	revokeCreds.clientID = clientID
	revokeCreds.clientSecret = clientSecret
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

// Classic PAT: ghp_ + 36 base62 chars.
// Fine-grained PAT: github_pat_ + 82 chars from [A-Za-z0-9_].
//
// Other GitHub token shapes (gho_/ghs_/ghu_/ghr_) share the ghp_ regex
// shape but have distinct semantics — surfaced via tokenType().
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

// Verify implements detectors.Verifier with the bool return shape the
// engine and the verifycoverage classifier expect. The richer
// metadata-bearing path lives in verifyWithMetadata so FromData can fold
// it into ExtraData without changing the interface contract.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	verified, _, err := verifyWithMetadata(ctx, secret)
	return verified, err
}

// verifyWithMetadata calls GET /user and returns the verification
// outcome plus blast-radius metadata. Failure modes:
//
//   - HTTP 200       → verified=true, metadata populated
//   - HTTP 401/403   → verified=false, no metadata, no error
//   - HTTP 429       → verified=false, no error (rate-limited; same
//     policy as the original Verify)
//   - transport err  → verified=false, error surfaced
//
// metadata is best-effort: a missing X-OAuth-Scopes header (fine-
// grained tokens do not set it) just leaves github_scopes absent.
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
		// Decode the small subset of the user payload we surface. Read
		// is bounded to 64 KiB so a hostile mock cannot exhaust memory.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		meta := buildMetadata(resp.Header, body)
		return true, meta, nil
	case http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}
}

// buildMetadata extracts the blast-radius surface from the GET /user
// response. Headers carry OAuth scopes and token expiration; the body
// carries the authenticated identity.
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

// splitAndTrim splits s on sep and trims whitespace from each element,
// dropping empties. Used for the X-OAuth-Scopes header which may use
// "scope, scope2" or "scope,scope2" depending on the upstream version.
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

// Revoke implements detectors.Revoker for GitHub-issued OAuth tokens.
//
// The endpoint is `DELETE /applications/{client_id}/token` with HTTP
// Basic auth (client_id:client_secret) and a JSON body
// `{"access_token": "<token>"}`. GitHub's documented response codes:
//
//   - 204 No Content    -> token revoked. RevokeResult.Revoked = true.
//   - 422 Unprocessable -> token did not belong to this OAuth app
//     (typical for raw user PATs). Revoked = false; non-fatal err in
//     RevokeResult.Err so the caller can distinguish "we tried, the
//     provider declined" from "we couldn't reach the provider".
//   - 404 Not Found     -> token already revoked / never existed.
//     Revoked = true (idempotency contract — second-call against an
//     already-revoked secret MUST NOT hard-fail).
//   - other             -> hard error via the second return value.
//
// Revoke is irreversible. Per ADR-0001 D6 the CLI gates this behind
// `--confirm` / `--dry-run` and the env var PLENO_DLP_ALLOW_REVOKE=1;
// the detector itself does NOT enforce any local gate so dry-run /
// confirmation policy lives uniformly at the CLI boundary.
func (Scanner) Revoke(ctx context.Context, secret string) (detectors.RevokeResult, error) {
	if secret == "" {
		return detectors.RevokeResult{}, errors.New("github: revoke: empty secret")
	}
	clientID, clientSecret := loadRevokeCreds()
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
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
