// Distinct from the classic ghp_/gho_/ghu_/ghs_/ghr_ GitHub detector because
// the prefix and length are structurally different.
package githubfinegrained

import (
	"context"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.github.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// Fine-grained PAT layout: github_pat_<22 base62>_<59 base62>
var tokenRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}\b`) })

const fineGrainedTokenLen = len("github_pat_") + 82

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.GitHubFineGrained }

func (Scanner) Keywords() []string { return []string{"github_pat_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !detectors.HasWordRunCandidate(data, "github_pat_", fineGrainedTokenLen) {
		return nil, nil
	}
	hits := detectors.FindAllLeftWordBoundary(tokenRe(), data)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[0]:h[1]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.GitHubFineGrained,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/vnd.github+json")

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
	if len(t) <= 15 {
		return t
	}
	return t[:15] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
