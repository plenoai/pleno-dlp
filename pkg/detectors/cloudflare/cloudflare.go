// Package cloudflare detects Cloudflare API tokens (40-char URL-safe) when
// they appear near a "cloudflare" or CF_API_TOKEN keyword, and verifies them
// at /client/v4/user/tokens/verify. On a verified hit the detector also
// queries /client/v4/accounts and stamps ExtraData with the token identity
// and the accounts it can reach — driftwood pattern: a verified Cloudflare
// token at a Fortune-500 account is a different incident than one against a
// hobby account, and triagers shouldn't have to issue extra API calls to
// tell them apart.
package cloudflare

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.cloudflare.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 40 chars from the URL-safe alphabet. The shape is generic, so we only emit
// matches when a co-occurring "cloudflare" / CF_API_TOKEN keyword is in the
// surrounding 256-byte window.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40})\b`)

var contextKeywords = []string{"cloudflare", "CF_API_TOKEN", "CF_TOKEN"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Cloudflare }

func (Scanner) Keywords() []string { return []string{"cloudflare", "CF_API_TOKEN", "CF_TOKEN"} }

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
		// Require co-occurrence — without it, this regex would explode with
		// false positives on every base64 chunk.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.Cloudflare,
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
		if strings.Contains(window, strings.ToLower(kw)) {
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/client/v4/user/tokens/verify", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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

	var body struct {
		Result struct {
			ID        string `json:"id"`
			Status    string `json:"status"`
			NotBefore string `json:"not_before"`
			ExpiresOn string `json:"expires_on"`
		} `json:"result"`
		Success bool `json:"success"`
	}
	meta := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		if body.Result.ID != "" {
			meta["cf_token_id"] = body.Result.ID
		}
		if body.Result.Status != "" {
			meta["cf_token_status"] = body.Result.Status
			if !strings.EqualFold(body.Result.Status, "active") {
				meta["cf_token_inactive"] = "true"
			}
		}
		if body.Result.ExpiresOn != "" {
			meta["cf_token_expires_on"] = body.Result.ExpiresOn
		}
		if body.Result.NotBefore != "" {
			meta["cf_token_not_before"] = body.Result.NotBefore
		}
	}

	// Best-effort: enumerate accessible accounts. This is the blast-radius
	// signal — same key against {personal hobby account} vs {Fortune-500} is
	// a wildly different incident. We tolerate failure here; the verify
	// itself has already succeeded, and triage just gets less context.
	if accounts := listAccounts(ctx, secret); len(accounts) > 0 {
		meta["cf_accounts_count"] = strconv.Itoa(len(accounts))
		// Surface up to 5 names so the field stays bounded; if there are
		// more, signal it explicitly so the triager knows to look.
		names := make([]string, 0, len(accounts))
		for _, a := range accounts {
			if a.Name != "" {
				names = append(names, a.Name)
			}
		}
		sort.Strings(names)
		if len(names) > 5 {
			names = append(names[:5], "…")
		}
		if len(names) > 0 {
			meta["cf_account_names"] = strings.Join(names, ",")
		}
	}
	return true, meta, nil
}

type cfAccount struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func listAccounts(ctx context.Context, secret string) []cfAccount {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/client/v4/accounts?per_page=50", nil)
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
	var body struct {
		Result  []cfAccount `json:"result"`
		Success bool        `json:"success"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	if !body.Success {
		return nil
	}
	return body.Result
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
