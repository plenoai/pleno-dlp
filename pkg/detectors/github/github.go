// Package github detects GitHub Personal Access Tokens (classic and
// fine-grained) and verifies them against api.github.com/user.
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
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is overridable from tests so verification can hit an httptest server.
var apiBase = "https://api.github.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Env variable names for the OAuth App credential pair Revoke needs.
// Documented here so cmd/pleno-dlp/cmd/revoke.go and
// docs/revoke-support.md stay in sync with the canonical source.
const (
	EnvClientID     = "PLENO_DLP_REVOKE_GITHUB_CLIENT_ID"
	EnvClientSecret = "PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET"
)

// revokeCreds holds the OAuth app credentials Revoke uses. The CLI sets
// them via SetRevokeCredentials before dispatching; tests do the same.
// When unset, Revoke falls back to the env vars above and otherwise errors. We keep
// these in package scope rather than on Scanner because Scanner is a
// value type registered through detectors.Register and shared across
// detector dispatch — mutating the registered instance is racy. A
// package-level mutex-guarded struct is simpler and matches the apiBase
// override pattern.
var (
	revokeCredsMu sync.RWMutex
	revokeCreds   struct {
		clientID     string
		clientSecret string
	}
)

// SetRevokeCredentials wires the OAuth app credentials Revoke uses. The
// CLI calls this from `pleno-dlp revoke github`. Calling with both
// arguments empty clears prior state (useful in tests).
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
		res := detectors.Result{
			DetectorType: detectors.GitHub,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "token "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusTooManyRequests:
		// Treat rate-limit as unverified rather than blocking the scan.
		return false, nil
	default:
		return false, nil
	}
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
//
// ProviderID is left empty: the DELETE endpoint does not return a
// payload (204), and we deliberately do not echo the secret as an id.
// Audit logs cross-reference revocations via the (RevokedAt, app
// client_id) pair recorded by the CLI.
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
		// Idempotent: token already gone.
		return detectors.RevokeResult{Revoked: true, RevokedAt: now, ProviderID: clientID, Err: errors.New("github: token already revoked or never existed")}, nil
	case http.StatusUnprocessableEntity:
		// Token didn't belong to this OAuth app. Non-fatal: caller may
		// retry against a different app or treat as "not ours".
		return detectors.RevokeResult{Revoked: false, ProviderID: clientID, Err: errors.New("github: token is not owned by the configured OAuth app (HTTP 422)")}, nil
	case http.StatusUnauthorized:
		return detectors.RevokeResult{}, fmt.Errorf("github: revoke: OAuth app credentials rejected (HTTP 401) — check %s / %s", EnvClientID, EnvClientSecret)
	case http.StatusTooManyRequests:
		// Don't retry — same policy as Verify. Caller decides whether
		// to back off and try again later.
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
