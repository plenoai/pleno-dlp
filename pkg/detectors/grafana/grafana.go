// A Grafana service-account token is itself a Bearer credential the Grafana
// HTTP API accepts directly, so a live verify cannot yield a false positive.
// The only obstacle is the per-instance host, which isn't carried in the
// token shape: Verify no-ops when apiBase is empty, so the detector ships
// verified-capable but defaults to surfacing tokens unverified until an
// operator supplies the host.
package grafana

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	acceptCodes = []int{http.StatusOK}
	rejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

var tokenRe = regexp.MustCompile(`\b(glsa_[A-Za-z0-9]{32}_[a-f0-9]{8})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Grafana }

func (Scanner) Keywords() []string { return []string{"glsa_"} }

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
			DetectorType: detectors.Grafana,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, err, acceptCodes, rejectCodes)
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
