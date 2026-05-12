// Package pagerduty detects PagerDuty REST API tokens (20-char alnum) and
// verifies them against /users/me (user-scoped) with /users as a fallback
// for General Access (account-scoped) tokens. On a verified hit the
// detector decodes the user identity and role so triagers can immediately
// see whether the leaked token belongs to an admin/owner — driftwood
// pattern.
//
// PagerDuty's token shape is a generic 20 characters from [A-Za-z0-9_-],
// which would explode with false positives if scanned blindly. We require
// a co-occurring "pagerduty" / "PD_API_KEY" keyword in the surrounding
// 256-byte window — same gating model as the cloudflare detector.
package pagerduty

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.pagerduty.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{20})\b`)

// keywordRe is the anchored PagerDuty marker. The bare keyword
// `pagerduty` is unique enough on its own but the prefilter may admit
// chunks where `pagerduty` occurs only as a substring of an unrelated
// English word; require word-bounded `\bpagerduty\b` plus credential
// anchors to be sure.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bpagerduty\b` +
	`|\bpd_api_key\b` +
	`|\bpd_token\b` +
	`|\bapi\.pagerduty\.com\b` +
	`|\bpagerduty[_\-](?:api|token|key|secret)` +
	`)`)

// PagerDuty roles that can mutate account-wide configuration: rotations,
// services, integrations, billing. A leaked token at any of these is
// effectively account takeover.
var privilegedRoles = map[string]struct{}{
	"admin":           {},
	"account_owner":   {},
	"owner":           {},
	"global_admin":    {},
	"team_responder":  {}, // can ack incidents account-wide
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PagerDuty }

func (Scanner) Keywords() []string { return []string{"pagerduty", "PD_API_KEY", "PD_TOKEN"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}

	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Mandatory co-occurrence — without a keyword in the window, every
		// 20-char base64-ish chunk would surface.
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.PagerDuty,
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

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
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

	// /users/me works only for User API keys (created by a real user).
	// General Access (account-wide) tokens get 404 here. Try this first
	// because it gives us the richest blast-radius signal: the user's role.
	user, status, err := getUsersMe(ctx, secret)
	if err != nil {
		return false, nil, err
	}
	if status == http.StatusOK && user != nil {
		meta := map[string]string{"pd_token_kind": "user"}
		if user.ID != "" {
			meta["pd_user_id"] = user.ID
		}
		if user.Name != "" {
			meta["pd_user_name"] = user.Name
		}
		if user.Email != "" {
			meta["pd_user_email"] = user.Email
		}
		if user.Role != "" {
			meta["pd_user_role"] = user.Role
			if _, ok := privilegedRoles[user.Role]; ok {
				meta["pd_privileged"] = "true"
			}
		}
		return true, meta, nil
	}
	// 401/403 means the token is bad — don't fall back, just report.
	if status == http.StatusUnauthorized || status == http.StatusForbidden {
		return false, nil, nil
	}

	// 404 (or anything else) → fall back to /users to confirm validity for
	// a General Access token.
	ok, err := pingUsers(ctx, secret)
	if err != nil {
		return false, nil, err
	}
	if !ok {
		return false, nil, nil
	}
	// General Access tokens are account-scoped → effectively admin.
	return true, map[string]string{
		"pd_token_kind": "general-access",
		"pd_privileged": "true",
	}, nil
}

type pdUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

func getUsersMe(ctx context.Context, secret string) (*pdUser, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/users/me", nil)
	if err != nil {
		return nil, 0, err
	}
	setAuthHeaders(req, secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, nil
	}
	var body struct {
		User pdUser `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return &pdUser{}, http.StatusOK, nil
	}
	return &body.User, http.StatusOK, nil
}

func pingUsers(ctx context.Context, secret string) (bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/users?limit=1", nil)
	if err != nil {
		return false, err
	}
	setAuthHeaders(req, secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

func setAuthHeaders(req *http.Request, secret string) {
	req.Header.Set("Authorization", "Token token="+secret)
	req.Header.Set("Accept", "application/vnd.pagerduty+json;version=2")
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
