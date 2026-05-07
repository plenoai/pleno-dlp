// Package terraformcloudteam detects Terraform Cloud / Enterprise team API
// tokens. Team tokens share the `<14 alnum>.atlasv1.<60+>` shape with user
// tokens (handled by pkg/detectors/terraformcloud), but have different
// rotation guidance — team tokens are tied to a workspace team and are
// typically rotated by an admin without the issuing user's involvement.
//
// We disambiguate by requiring co-occurrence with a `team` / `team_token`
// keyword in the same 256-byte window. Verify uses the same /api/v2/account/
// details endpoint — Terraform Cloud surfaces team membership in the
// response so a 200 confirms the token is live regardless of scope.
package terraformcloudteam

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://app.terraform.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})\b`)

// Both `team` and `tfe_team_token` style cues are accepted.
var contextKeywords = []string{"team_token", "team-token", "tfeteam", "tfe_team", "terraform_team", "tfc_team"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TerraformCloudTeam }

func (Scanner) Keywords() []string { return []string{".atlasv1.", "team_token"} }

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
		// Only emit when the chunk explicitly marks this as a team token.
		// Lone atlasv1 tokens belong to pkg/detectors/terraformcloud (user
		// scope by default) — we don't want both detectors firing on the
		// same string.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.TerraformCloudTeam,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    map[string]string{"scope": "team"},
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v2/account/details", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/vnd.api+json")

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
	if len(t) <= 23 {
		return t
	}
	return t[:23] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
