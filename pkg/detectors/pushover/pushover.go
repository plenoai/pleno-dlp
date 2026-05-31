// Package pushover detects Pushover application API tokens — 30-char
// alphanumeric strings near the `pushover` keyword. Verified via
// /1/users/validate.json on api.pushover.net using POST form `token=<token>`
// (Pushover requires a user key for full validation, so we use the
// /1/sounds.json endpoint instead which only requires a valid app token).
package pushover

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.pushover.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Pushover application tokens are documented as exactly 30 characters,
// case-sensitive, charset [A-Za-z0-9], with no distinguishing prefix.
// Source: https://pushover.net/api — "Application tokens are case-sensitive,
// 30 characters long, and may contain the character set [A-Za-z0-9]."
// (User/group keys share the same 30-char [A-Za-z0-9] shape.)
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{30})\b`)

// armRe is the assignment-style Pushover reference that must appear within the
// proximity window. A bare "pushover" substring (URLs, package names, prose) is
// too weak. The token has no prefix to anchor on, so this arm carries the
// false-positive load alongside the entropy floor. It requires the `pushover`
// keyword, an optional `_app` / `_token` / `_key` / `_secret` / `_api_token`
// qualifier, and an assignment delimiter (`=` or `:`) so a token merely sitting
// near the word "pushover" in prose no longer arms. Covers the
// vendor[_-]?(api[_-]?)?(token|key|secret) shape and the config-key forms.
var armRe = regexp.MustCompile(`(?i)pushover([_\-]?(app|api[_\-]?(token|key|secret)|token|key|secret))?\s*[:=]`)

// minEntropy rejects low-information 30-char alphanumeric runs that clear the
// regex but are not random tokens (structured identifiers, padded names). The
// charset is high-variety (62 symbols), so the 3.5 bits/char floor from the
// fixed-length-no-prefix rubric branch applies without over-culling.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pushover }

func (Scanner) Keywords() []string { return []string{"pushover"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: 30-char alphanumeric runs are common (hashes, ids,
		// padded names). The documented charset is high-variety, so a 3.5
		// bits/char floor rejects structured runs without culling real tokens.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Pushover,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether an assignment-style `pushover[...]:=` reference
// appears within a tight window on either side of the token. Radius 64 (down
// from 256) keeps the arm local to the candidate; the bidirectional window lets
// a token defined just before or after a `pushover_token=` key still arm.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("token", secret)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/1/sounds.json", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
