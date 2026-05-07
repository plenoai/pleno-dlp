// Package signalwire detects SignalWire Project ID + API token pairs near
// the `signalwire` keyword. Verified via /api/laml/2010-04-01/Accounts on
// the per-space host (`<space>.signalwire.com`) using HTTP Basic auth
// (project as username, token as password). Unverified-by-default — the
// space host isn't in the chunk; verify only fires when an apiBase override
// is supplied. Raw carries the project_id, RawV2 the token.
package signalwire

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

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,128})\b`)

var contextKeywords = []string{"signalwire"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SignalWire }

func (Scanner) Keywords() []string { return []string{"signalwire"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	id, token := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.SignalWire,
		Raw:          []byte(id),
		RawV2:        []byte(token),
		Redacted:     redact(id),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, id+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/laml/2010-04-01/Accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, tok)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
