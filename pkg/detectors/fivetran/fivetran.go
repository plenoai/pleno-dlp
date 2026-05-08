// Package fivetran detects Fivetran API key + secret pairs near the
// `fivetran` keyword. Verified via /v1/users on api.fivetran.com using
// HTTP Basic auth (key as username, secret as password).
package fivetran

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.fivetran.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Fivetran API keys/secrets are 20 alnum each. We pair them by proximity.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{20})\b`)

var contextKeywords = []string{"fivetran"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Fivetran }

func (Scanner) Keywords() []string { return []string{"fivetran"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	// Pair adjacent matches that both fall inside a fivetran keyword window.
	var paired [][2]string
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(hits); i++ {
		a := string(data[hits[i][2]:hits[i][3]])
		b := string(data[hits[i+1][2]:hits[i+1][3]])
		if a == b {
			continue
		}
		if !nearKeyword(lower, hits[i][2], hits[i+1][3]) {
			continue
		}
		k := a + ":" + b
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		paired = append(paired, [2]string{a, b})
	}
	if len(paired) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(paired))
	for _, p := range paired {
		key, secret := p[0], p[1]
		res := detectors.Result{
			DetectorType: detectors.Fivetran,
			Raw:          []byte(key),
			RawV2:        []byte(key + ":" + secret),
			Redacted:     redact(key),
		}
		if verify {
			v, err := s.Verify(ctx, key+":"+secret)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
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

func (Scanner) Verify(ctx context.Context, pair string) (bool, error) {
	parts := strings.SplitN(pair, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(parts[0], parts[1])
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
