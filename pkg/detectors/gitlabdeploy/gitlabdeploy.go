// Package gitlabdeploy detects GitLab project / group / deploy tokens
// (`gldt-` prefix and adjacent variants) — distinct from the user PAT
// (`glpat-`) owned by `pkg/detectors/gitlab`.
//
// Project / deploy / group tokens are scoped to a single project or group and
// are commonly minted into CI environments. Verify hits gitlab.com's
// `/api/v4/user`, which honours the same Bearer header as PATs and returns
// 200 when the token is currently valid.
package gitlabdeploy

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://gitlab.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Token shapes (per GitLab's documented prefixes):
//   - gldt-<20+ chars> deploy token
//   - glptt-<20+ chars> project trigger token
//   - glagent-<20+ chars> agent token
//   - glsoat-<20+ chars> SCIM OAuth access token
//   - glcbt-<20+ chars> CI build / job token (when leaked verbatim)
//   - glrt-<20+ chars> runner authentication token
var tokenRe = regexp.MustCompile(`\b((?:gldt|glptt|glagent|glsoat|glcbt|glrt)-[A-Za-z0-9_-]{20,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitLabDeploy }

// All prefixes start with `gl` and are unmistakable; we list the most common
// few so the engine's keyword index can short-circuit cheaply.
func (Scanner) Keywords() []string {
	return []string{"gldt-", "glptt-", "glagent-", "glsoat-", "glcbt-", "glrt-"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.GitLabDeploy,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyToken(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret)
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v4/user", nil)
	if err != nil {
		return false, err
	}
	// GitLab honours both `Authorization: Bearer …` and the older
	// `PRIVATE-TOKEN: …` header. Bearer is the documented current path.
	req.Header.Set("Authorization", "Bearer "+token)

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
	if len(t) <= 10 {
		return t
	}
	return t[:10] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
