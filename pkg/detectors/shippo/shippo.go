// Package shippo detects Shippo API keys — `shippo_(live|test)_<40+ alnum>`
// prefix-keyed strings. Verified via /v1/addresses on api.goshippo.com with
// `ShippoToken <key>` auth. Live keys (`shippo_live_`) surface
// SeverityCritical via DefaultSeverity when verified.
package shippo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.goshippo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(shippo_(?:live|test)_[A-Za-z0-9]{40,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Shippo }

func (Scanner) Keywords() []string { return []string{"shippo_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, m := range hits {
		token := string(m[1])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Shippo,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/addresses", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "ShippoToken "+secret)
	req.Header.Set("Accept", "application/json")
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
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
