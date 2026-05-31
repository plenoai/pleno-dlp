// Package customerio detects Customer.io tracking credentials — a paired
// site_id + api_key (each 20-char alphanumeric) near the `customerio` /
// `customer_io` keyword. Verified via /api/v1/customers on track.customer.io
// using HTTP Basic auth (site_id as user, api_key as password). Raw carries
// the site_id, RawV2 carries the api_key.
package customerio

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://track.customer.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// site_id and api_key are both 20-char alphanumeric (no separators). The
// 20-char base62 shape and the absence of any credential-borne prefix are
// confirmed by the upstream trufflehog detector
// (github.com/trufflesecurity/trufflehog pkg/detectors/customerio:
// `[a-z0-9A-Z]{20}`), which is the authoritative format for this port.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20})\b`)

// minEntropy rejects low-information 20-char runs (padded ids, repeated
// chars, structured slugs) that clear the regex but lack key-grade
// randomness. 3.5 bits/char suits the base62 charset.
const minEntropy = 3.5

// contextRe is the windowed keyword gate. A bare strings.Contains over a
// radius-256 window matched far-away occurrences of the brand word; the
// assignment-anchor arm regex pins the keyword to a credential-like
// assignment so only genuine site_id/api_key declarations arm a hit. The
// bare brand words stay in Keywords() as the engine prefilter.
var contextRe = regexp.MustCompile(`(?i)(customer[._]?io|cio)[_-]?(site|api)[_-]?(id|key)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CustomerIO }

func (Scanner) Keywords() []string { return []string{"customerio", "customer_io", "customer.io"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		siteID := string(data[h[2]:h[3]])
		if _, dup := seen[siteID]; dup {
			continue
		}
		if !detectors.HasMinEntropy(siteID, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		var apiKey string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand != siteID && detectors.HasMinEntropy(cand, minEntropy) && nearKeyword(lower, h2[2], h2[3]) {
				apiKey = cand
				break
			}
		}
		if apiKey == "" {
			continue
		}
		seen[siteID] = struct{}{}
		seen[apiKey] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.CustomerIO,
			Raw:          []byte(siteID),
			RawV2:        []byte(apiKey),
			Redacted:     redact(siteID),
		}
		if verify {
			v, err := s.Verify(ctx, siteID+":"+apiKey)
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

func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return contextRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	siteID, apiKey := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// /api/v1/customers requires GET with Basic auth — 200 means valid creds.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/customers", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(siteID, apiKey)
	req.Header.Set("Accept", "application/json")
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
