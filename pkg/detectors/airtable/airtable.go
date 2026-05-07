// Package airtable detects Airtable PATs (`pat<14>.<64-hex>`) and the legacy
// `key<14>` API keys, verifying via /v0/meta/bases.
package airtable

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.airtable.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// PAT shape per Airtable docs: `pat` + 14 alnum + `.` + 64 hex. Distinct
	// enough to skip the keyword gate.
	patRe = regexp.MustCompile(`\b(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})\b`)
	// Legacy API key: `key` + 14 alnum. The 17-char "key…" prefix is shared
	// by other systems, so we keyword-gate this branch.
	legacyRe = regexp.MustCompile(`\b(key[A-Za-z0-9]{14})\b`)
)

var contextKeywords = []string{"airtable", "airtable_api_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Airtable }

func (Scanner) Keywords() []string { return []string{"pat", "airtable"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	for _, m := range patRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Airtable,
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

	legacyHits := legacyRe.FindAllSubmatchIndex(data, -1)
	if len(legacyHits) > 0 {
		lower := strings.ToLower(string(data))
		for _, h := range legacyHits {
			token := string(data[h[2]:h[3]])
			if _, dup := seen[token]; dup {
				continue
			}
			if !nearKeyword(lower, h[2], h[3]) {
				continue
			}
			seen[token] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Airtable,
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
	}

	if len(out) == 0 {
		return nil, nil
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v0/meta/bases", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
