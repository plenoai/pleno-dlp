// Package etherscan detects Etherscan API keys — 34-char alnum strings
// near the `etherscan` keyword. Verified via the read-only V2 eth supply
// endpoint on api.etherscan.io with the candidate key.
package etherscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.etherscan.io"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

const maxVerifyResponseBytes = 64 << 10

var tokenRe = regexp.MustCompile(`\b([A-Z0-9]{34})\b`)

var contextKeywords = []string{"etherscan"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Etherscan }

func (Scanner) Keywords() []string { return []string{"etherscan"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Etherscan,
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
	q := url.Values{}
	q.Set("chainid", "1")
	q.Set("module", "stats")
	q.Set("action", "ethsupply")
	q.Set("apikey", secret)
	target := strings.TrimRight(apiBase, "/") + "/v2/api?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false, fmt.Errorf("etherscan verify: build request")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// net/url errors may embed the complete request URL, including the API
		// key query parameter. Keep verification diagnostics secret-free.
		return false, fmt.Errorf("etherscan verify: request failed")
	}
	accepted, classifyErr := detectors.ClassifyVerifyHTTP(
		resp,
		nil,
		[]int{http.StatusOK},
		nil,
	)
	if resp == nil {
		return accepted, classifyErr
	}
	defer resp.Body.Close()
	if classifyErr != nil || !accepted {
		return accepted, classifyErr
	}
	return classifyVerifyResponse(resp.Body)
}

func classifyVerifyResponse(body io.Reader) (bool, error) {
	payload, err := io.ReadAll(io.LimitReader(body, maxVerifyResponseBytes+1))
	if err != nil {
		return false, fmt.Errorf("etherscan verify: read response: %w", err)
	}
	if len(payload) > maxVerifyResponseBytes {
		return false, fmt.Errorf("etherscan verify: response exceeds %d bytes", maxVerifyResponseBytes)
	}

	var envelope struct {
		Status  string          `json:"status"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return false, fmt.Errorf("etherscan verify: malformed JSON response: %w", err)
	}
	if len(envelope.Result) == 0 {
		return false, fmt.Errorf("etherscan verify: ambiguous provider response")
	}

	var result string
	if err := json.Unmarshal(envelope.Result, &result); err != nil {
		return false, fmt.Errorf("etherscan verify: unexpected result shape")
	}

	status := strings.TrimSpace(envelope.Status)
	message := strings.TrimSpace(envelope.Message)
	result = strings.TrimSpace(result)
	if status == "1" && message == "OK" && result != "" {
		return true, nil
	}
	if status == "0" && message == "NOTOK" &&
		strings.Contains(strings.ToLower(result), "invalid api key") {
		return false, nil
	}
	return false, fmt.Errorf("etherscan verify: ambiguous provider response")
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
