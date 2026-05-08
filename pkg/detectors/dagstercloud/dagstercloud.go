// Package dagstercloud detects Dagster Cloud user / agent tokens
// (`dgc_` or `agent:` prefix). Verified via /graphql on
// dagster.cloud with the Dagster-Cloud-Api-Token header.
package dagstercloud

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://dagster.cloud"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(dgc_[A-Za-z0-9_\-]{30,128})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DagsterCloud }

func (Scanner) Keywords() []string { return []string{"dgc_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.DagsterCloud,
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
	body := strings.NewReader(`{"query":"{ currentUser { email } }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/graphql", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Dagster-Cloud-Api-Token", secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
