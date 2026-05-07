// Package telegram detects Telegram Bot API tokens (`<bot_id>:<35-char base64>`)
// and verifies them via /getMe. The shape is documented and stable; the colon
// + bot id prefix make it precise enough to surface without a keyword gate.
package telegram

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.telegram.org"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Telegram bot tokens are <8-10 digit bot id>:<35-char base64url-ish>. The
// 35-char run is the documented length; we accept 30+ to absorb future
// variations without a regex churn.
var tokenRe = regexp.MustCompile(`\b([0-9]{6,12}:[A-Za-z0-9_-]{30,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Telegram }

// "bot" alone is too noisy; the colon-bracketed shape is precise. Prefilter
// on common keyword forms.
func (Scanner) Keywords() []string { return []string{"telegram", "bot"} }

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
		res := detectors.Result{
			DetectorType: detectors.Telegram,
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

	// Telegram embeds the token in the path: /bot<token>/getMe.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/bot"+secret+"/getMe", nil)
	if err != nil {
		return false, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusTooManyRequests:
		// Telegram returns 404 for invalid tokens, not 401.
		return false, nil
	default:
		return false, nil
	}
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
