// Package pardot detects Salesforce Pardot / Account Engagement business
// unit id + access token pairs near the `pardot` keyword. Verified via
// /api/v5/objects/account on pi.pardot.com sending Bearer auth and the
// Pardot-Business-Unit-Id header. Raw carries the business unit id, RawV2
// the access token.
package pardot

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://pi.pardot.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{18,256})\b`)

var contextKeywords = []string{"pardot"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pardot }

func (Scanner) Keywords() []string { return []string{"pardot"} }

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
	id, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.Pardot,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify {
		v, err := s.Verify(ctx, id+":"+secret)
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	bu, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v5/objects/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Pardot-Business-Unit-Id", bu)
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
