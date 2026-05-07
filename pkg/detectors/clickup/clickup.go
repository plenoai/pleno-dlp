// Package clickup detects ClickUp personal API tokens (`pk_<digits>_<32
// uppercase alnum>`) and verifies them against /api/v2/user.
//
// ClickUp tokens grant the issuing user's full workspace scope. Verify is a
// cheap GET; we use that instead of a destructive endpoint. SeverityHigh
// is the package default for unverified hits; verified hits are upgraded to
// Critical via the engine's Verified-implies-Critical rule.
package clickup

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.clickup.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// pk_<digits>_<32 uppercase alnum>. The leading `pk_` and the digit
// segment are distinctive enough that we don't require a co-occurring
// keyword; the suffix shape (32 uppercase A-Z0-9) is too narrow for
// accidental collisions.
var keyRe = regexp.MustCompile(`\b(pk_[0-9]{6,8}_[A-Z0-9]{32})\b`)

var contextKeywords = []string{"clickup", "click_up", "click-up"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ClickUp }

// `pk_` is shared with Klaviyo; the keyword prefilter still hits clickup
// because real-world configs nearly always say `clickup` somewhere in
// the file. Including `pk_` here would over-trigger.
func (Scanner) Keywords() []string { return []string{"clickup", "pk_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Co-occurrence keeps us off Klaviyo's `pk_` keyspace and any other
		// `pk_…` shape that happens to land in the corpus.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ClickUp,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/user", nil)
	if err != nil {
		return false, err
	}
	// ClickUp accepts the raw token as Authorization header (no Bearer prefix).
	// Bearer also works in practice; we use the documented form to keep audit
	// logs clean.
	req.Header.Set("Authorization", secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
