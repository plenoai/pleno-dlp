// Package apollo detects Apollo.io sales-engagement API keys — long alnum
// strings near the `apollo` keyword. Verified via /api/v1/auth/health on
// api.apollo.io with X-Api-Key header.
package apollo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.apollo.io"

const maxVerificationResponseBytes = 1 << 20

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// Keep the candidate shape and proximity aligned with the provider detector
// we compare against: "apollo" must precede a 22-character alphanumeric key
// by at most 40 bytes. The previous bidirectional 256-byte window admitted
// unrelated identifiers and dominated large-repository false positives.
var tokenRe = regexp.MustCompile(`(?i:apollo)(?:.|[\n\r]){0,40}?\b([A-Za-z0-9]{22})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Apollo }

func (Scanner) Keywords() []string { return []string{"apollo"} }

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
			DetectorType: detectors.Apollo,
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
	// Apollo documents this endpoint and the two true fields as the API-key
	// readiness check: https://docs.apollo.io/docs/test-api-key
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/auth/health", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Api-Key", secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	accepted, err := detectors.ClassifyVerifyHTTP(
		resp,
		err,
		[]int{http.StatusOK},
		[]int{http.StatusUnauthorized},
	)
	if err != nil || !accepted {
		return false, err
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxVerificationResponseBytes+1))
	if err != nil {
		return false, fmt.Errorf("verify: read Apollo health response: %w", err)
	}
	if len(body) > maxVerificationResponseBytes {
		return false, fmt.Errorf("verify: Apollo health response exceeds %d bytes", maxVerificationResponseBytes)
	}
	var health struct {
		Healthy    *bool `json:"healthy"`
		IsLoggedIn *bool `json:"is_logged_in"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&health); err != nil {
		return false, fmt.Errorf("verify: decode Apollo health response: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return false, fmt.Errorf("verify: Apollo health response contains trailing data")
	}
	if health.Healthy == nil || health.IsLoggedIn == nil {
		return false, fmt.Errorf("verify: Apollo health response is missing required fields")
	}
	if !*health.IsLoggedIn {
		return false, nil
	}
	if !*health.Healthy {
		return false, fmt.Errorf("verify: Apollo authenticated session is unhealthy")
	}
	return true, nil
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
