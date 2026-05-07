// Package discord detects Discord bot tokens (`<base64-id>.<base64-ts>.<hmac>`)
// and verifies them against /users/@me with the `Bot <token>` Authorization
// scheme.
//
// Discord's modern token shape encodes the snowflake user id, an issuance
// timestamp, and an HMAC. Each segment is base64url. The 24-char first
// segment is distinctive enough that the keyword gate is optional.
package discord

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://discord.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `<24+>.<6+>.<27+>` base64url segments. We allow a wider lower bound on the
// last segment because Discord rotated to longer HMACs in late 2023.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{24,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Discord }

func (Scanner) Keywords() []string { return []string{"discord", "DISCORD_TOKEN", "DISCORD_BOT"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
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
			DetectorType: detectors.Discord,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v10/users/@me", nil)
	if err != nil {
		return false, err
	}
	// Discord uses `Bot <token>` rather than `Bearer`. Using `Bearer` here
	// would always 401 even on valid bot tokens, inverting the verify signal.
	req.Header.Set("Authorization", "Bot "+secret)

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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
