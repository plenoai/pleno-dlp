// Package dopplercli detects Doppler CLI tokens (`dp.cli.…`).
//
// The existing `pkg/detectors/doppler` package handles service / personal /
// SCIM / service-account scopes (st/pt/sa/scim and the legacy ct CLI scope).
// dopplercli covers the newer `cli` scope that Doppler issues for CLI-only
// workflows — it has the same endpoint host as the other scopes but is
// distinguished by the prefix and verified against /v3/configs (which a CLI
// token can read but a service token cannot, in practice; this lets the
// scanner confirm which scope class the token belongs to).
package dopplercli

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.doppler.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `dp.cli.` + 40+ base64url chars. Anchored to the new prefix so it doesn't
// overlap with the existing doppler detector.
var tokenRe = regexp.MustCompile(`\b(dp\.cli\.[A-Za-z0-9_-]{40,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DopplerCLI }

func (Scanner) Keywords() []string { return []string{"dp.cli."} }

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
			DetectorType: detectors.DopplerCLI,
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

	// /v3/configs is the CLI-scope-readable endpoint. Service tokens get a
	// different shape on this same host (/v3/configs/secrets), and we
	// deliberately probe the configs index so a true CLI token returns 200.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v3/configs", nil)
	if err != nil {
		return false, err
	}
	// Doppler authenticates with Basic where the username is the token and
	// password is empty — same contract as service tokens.
	req.SetBasicAuth(secret, "")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusUnprocessableEntity:
		// 422 on this endpoint means "missing project query param" — the
		// token authenticated but the request was incomplete. We treat that
		// as verified=true because authentication is what we're confirming.
		if resp.StatusCode == http.StatusUnprocessableEntity {
			return true, nil
		}
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
