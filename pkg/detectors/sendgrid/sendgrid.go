// Package sendgrid detects SendGrid API keys (SG.<id>.<secret>) and verifies
// them against /v3/scopes. On a verified hit the detector decodes the scope
// list and surfaces what the key actually unlocks — driftwood pattern: a
// SendGrid key with `mail.send` is an email-fraud capability, while a key
// scoped only to `stats.read` is read-only telemetry. Triagers shouldn't
// have to issue a second API call to learn that.
package sendgrid

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sendgrid.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SendGrid keys: literal "SG." then 22-char id, dot, 43-char secret.
var keyRe = regexp.MustCompile(`\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b`)

// Scopes that grant either email-sending capability (fraud surface) or
// administrative control (privilege escalation). Sorted by leaf for stable
// matching against the dotted-namespace scopes returned by the API.
var privilegedScopes = map[string]struct{}{
	// Email send / batch / marketing — direct outbound abuse.
	"mail.send":                 {},
	"mail.batch.create":         {},
	"mail.batch.update":         {},
	"marketing.send":            {},
	"marketing.automation.send": {},
	"sender_verification_eligible": {},
	// API-key management — privilege escalation.
	"api_keys.create": {},
	"api_keys.update": {},
	"api_keys.delete": {},
	// Subuser / billing / SSO — tenant takeover.
	"subusers.create":     {},
	"subusers.delete":     {},
	"billing.update":      {},
	"sso.settings.update": {},
	"user.account.update": {},
	"user.email.update":   {},
	// Webhooks / partner settings — exfil + supply-chain.
	"partner_settings.update":      {},
	"user.webhooks.event.settings": {},
	"user.webhooks.parse.settings": {},
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SendGrid }

func (Scanner) Keywords() []string { return []string{"SG."} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.SendGrid,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v3/scopes", nil)
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
		Scopes []string `json:"scopes"`
	}
	meta := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		if len(body.Scopes) > 0 {
			scopes := append([]string(nil), body.Scopes...)
			sort.Strings(scopes)
			meta["sendgrid_scopes"] = strings.Join(scopes, ",")
			if priv := privilegedHits(scopes); len(priv) > 0 {
				meta["sendgrid_privileged"] = "true"
				meta["sendgrid_privileged_scopes"] = strings.Join(priv, ",")
			}
			// SendGrid Full Access keys return every scope in the catalog;
			// restricted keys return only what was granted. A practical
			// proxy for "this is a Full Access key" is presence of *all*
			// three core admin scopes that restricted keys can't grant
			// to themselves: api_keys.create, billing.read, user.email.update.
			if hasAll(scopes, "api_keys.create", "billing.read", "user.email.update") {
				meta["sendgrid_key_kind"] = "full-access"
			} else {
				meta["sendgrid_key_kind"] = "restricted"
			}
		} else {
			// Empty scope list with 200 means a Billing-Access-only key,
			// which has scopes but they aren't enumerated through this
			// endpoint. Mark it for the triager.
			meta["sendgrid_key_kind"] = "billing-or-empty"
		}
	}
	return true, meta, nil
}

func privilegedHits(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if _, ok := privilegedScopes[s]; ok {
			out = append(out, s)
		}
	}
	return out
}

func hasAll(scopes []string, want ...string) bool {
	idx := make(map[string]struct{}, len(scopes))
	for _, s := range scopes {
		idx[s] = struct{}{}
	}
	for _, w := range want {
		if _, ok := idx[w]; !ok {
			return false
		}
	}
	return true
}

func redact(t string) string {
	// Keep "SG." + first 4 of id segment.
	if len(t) <= 7 {
		return t
	}
	return t[:7] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
