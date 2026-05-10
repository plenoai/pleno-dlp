// Package slack detects Slack bot tokens (xoxb-…) and verifies them against
// auth.test.
//
// Revoke (issue #73) calls POST /api/auth.revoke on slack.com. Slack's
// API contract is unusual — every response is HTTP 200 and the
// success/failure signal is in the JSON body's `ok` field. Revoke
// honours that: `ok=true,revoked=true` is a successful revocation,
// while `token_revoked` / `invalid_auth` / `not_authed` errors are
// treated as idempotent successes (Revoked=true with a non-fatal
// diagnostic in RevokeResult.Err) so a second call against an already-
// revoked token does not hard-fail. HTTP 429 and transport failures
// surface via the second return value so callers can distinguish "we
// couldn't reach the provider" from "the provider said no". Revoke
// supports every Slack token shape (`xoxb-`, `xoxp-`, `xoxa-`, `xoxe-`,
// `xapp-`) since auth.revoke accepts any of them as the bearer.
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

// xoxb-<workspace_id>-<bot_id>-<secret>. The trailing run is base62-ish; we
// require at least 24 chars to avoid latching on truncated samples.
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
		res := detectors.Result{
			DetectorType: detectors.SlackBotToken,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/api/auth.test", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var body struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return false, nil
	}
	return body.OK, nil
}

// Revoke implements detectors.Revoker for Slack-issued bearer tokens.
//
// Slack's auth.revoke endpoint always returns HTTP 200 and encodes the
// outcome in the JSON body. The mapping here:
//
//   - {"ok":true,"revoked":true}              -> Revoked=true.
//   - {"ok":false,"error":"token_revoked"}    -> Revoked=true (idempotent;
//     the token was already revoked). Err carries the diagnostic.
//   - {"ok":false,"error":"invalid_auth"}     -> Revoked=true (idempotent;
//     either already revoked or never valid — both terminal states from
//     the caller's perspective).
//   - {"ok":false,"error":"not_authed"}       -> Revoked=true (same).
//   - {"ok":false,"error":"<other>"}          -> Revoked=false with the
//     provider error in RevokeResult.Err.
//   - HTTP 429                                -> hard error, no retry
//     (same policy as Verify; the caller decides whether to back off).
//   - HTTP 5xx / transport failure            -> hard error via second
//     return value so callers can distinguish "we couldn't reach the
//     provider" from "the provider said no".
//
// ProviderID is left empty: auth.revoke does not echo a token id, and
// we deliberately do not echo the secret as an id. Audit logs cross-
// reference revocations via the (RevokedAt, detector type) pair the
// CLI records.
//
// Revoke is irreversible. Per ADR-0001 D6 the CLI gates this behind
// `--confirm` / `--dry-run` and the env var PLENO_DLP_ALLOW_REVOKE=1;
// the detector itself does NOT enforce any local gate so the policy
// lives uniformly at the CLI boundary.
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
		// Slack's documented contract is "always 200"; anything else is
		// unexpected enough to surface as a hard error rather than a
		// silent unverified result.
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

// Compile-time interface checks.
var (
	_ detectors.Detector = Scanner{}
	_ detectors.Verifier = Scanner{}
	_ detectors.Revoker  = Scanner{}
)

func init() {
	detectors.Register(Scanner{})
}
