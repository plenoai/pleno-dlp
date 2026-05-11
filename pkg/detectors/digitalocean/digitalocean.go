// Package digitalocean detects DigitalOcean personal access tokens
// (dop_v1_<64 hex>) and verifies them via /v2/account. On a verified hit
// the detector decodes the account body and surfaces the email, status,
// team, and droplet/floating-IP limits — driftwood pattern: a leaked DO
// token on an active validated account with a high droplet limit is a
// billing-fraud / crypto-mining surface; one against a locked account
// is contained.
package digitalocean

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

var apiBase = "https://api.digitalocean.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// dop_v1_ prefix + 64 hex chars. The provider-specific prefix means the regex
// is precise enough that we don't need a co-occurring keyword.
var tokenRe = regexp.MustCompile(`\b(dop_v1_[a-f0-9]{64})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DigitalOcean }

func (Scanner) Keywords() []string { return []string{"dop_v1_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.DigitalOcean,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v2/account", nil)
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

	var body struct {
		Account struct {
			Email           string `json:"email"`
			UUID            string `json:"uuid"`
			EmailVerified   bool   `json:"email_verified"`
			Status          string `json:"status"`
			DropletLimit    int    `json:"droplet_limit"`
			FloatingIPLimit int    `json:"floating_ip_limit"`
			Team            struct {
				UUID string `json:"uuid"`
				Name string `json:"name"`
			} `json:"team"`
		} `json:"account"`
	}
	meta := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		acc := body.Account
		if acc.Email != "" {
			meta["do_email"] = acc.Email
		}
		if acc.UUID != "" {
			meta["do_user_uuid"] = acc.UUID
		}
		if acc.Status != "" {
			meta["do_status"] = acc.Status
		}
		meta["do_email_verified"] = strconv.FormatBool(acc.EmailVerified)
		if acc.DropletLimit > 0 {
			meta["do_droplet_limit"] = strconv.Itoa(acc.DropletLimit)
		}
		if acc.FloatingIPLimit > 0 {
			meta["do_floating_ip_limit"] = strconv.Itoa(acc.FloatingIPLimit)
		}
		if acc.Team.Name != "" {
			meta["do_team_name"] = acc.Team.Name
		}
		if acc.Team.UUID != "" {
			meta["do_team_uuid"] = acc.Team.UUID
		}
		// status: active = usable; warning = throttled but spinable; locked
		// = read-only; the DO API enumerates exactly these three.
		switch strings.ToLower(acc.Status) {
		case "locked":
			meta["do_account_locked"] = "true"
		case "active":
			if acc.EmailVerified {
				// Active + verified email = the token can spin up droplets,
				// which translates directly to crypto-mining / DDoS-source /
				// other billing-fraud surface. This is the dominant
				// blast-radius signal.
				meta["do_high_risk"] = "true"
			}
		}
	}
	return true, meta, nil
}

func redact(t string) string {
	// Keep "dop_v1_" prefix + first 4 of the hex tail.
	if len(t) <= 11 {
		return t
	}
	return t[:11] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
