// Package resend detects Resend API keys (`re_…`) and verifies them
// against /domains using Bearer auth.
//
// Resend keys grant the issuing workspace's email-sending scope. The `re_`
// prefix also appears in ordinary identifiers, so obvious snake_case
// identifiers are retained as candidates but do not trigger remote
// verification.
package resend

import (
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

var apiBase = "https://api.resend.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(re_[A-Za-z0-9_]{20,})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Resend }

func (Scanner) Keywords() []string { return []string{"re_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		token := string(match)
		if _, duplicate := seen[token]; duplicate {
			continue
		}
		seen[token] = struct{}{}
		result := detectors.Result{
			DetectorType: detectors.Resend,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && shouldVerify(token) {
			v, err := s.Verify(ctx, token)
			result.Verified = v
			result.VerificationErr = err
		}
		out = append(out, result)
	}
	return out, nil
}

func shouldVerify(token string) bool {
	// Resend publicly guarantees only the re_ prefix, so unfamiliar token
	// shapes still go to the provider. The narrow exception is an all-lowercase
	// body with multiple separators: this is the common snake_case identifier
	// collision behind large candidate storms, not the provider's documented
	// generated-key shape. Keeping the candidate in the result preserves the
	// detector contract and offline coverage.
	body := token[len("re_"):]
	if strings.Count(body, "_") < 2 {
		return true
	}
	for _, c := range body {
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/domains", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "pleno-dlp")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return false, fmt.Errorf("resend verify: read response: %w", err)
	}
	var apiErr struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return false, fmt.Errorf("resend verify: ambiguous HTTP %d response", resp.StatusCode)
	}
	switch apiErr.Name {
	case "restricted_api_key":
		// Sending-only keys cannot list domains, but the provider has
		// authenticated the key and reported its permission boundary.
		if resp.StatusCode == http.StatusUnauthorized {
			return true, nil
		}
	case "invalid_api_key":
		if resp.StatusCode == http.StatusForbidden {
			return false, nil
		}
	}
	return false, fmt.Errorf("resend verify: ambiguous HTTP %d response (%s)", resp.StatusCode, apiErr.Name)
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
