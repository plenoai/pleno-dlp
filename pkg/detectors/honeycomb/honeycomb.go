package honeycomb

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.honeycomb.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Modern ingest key: hcaik_ plus 58 base62 chars; the prefix is unique
	// enough to skip keyword gating.
	modernRe = regexp.MustCompile(`\b(hcaik_[A-Za-z0-9]{58})\b`)
	// Legacy 32-hex needs keyword gating.
	legacyRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

var contextKeywords = []string{"honeycomb", "honeycomb_api_key", "hny_api_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Honeycomb }

func (Scanner) Keywords() []string { return []string{"hcaik_", "honeycomb"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	for _, m := range modernRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Honeycomb,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyToken(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}

	lower := strings.ToLower(string(data))
	hits := legacyRe.FindAllSubmatchIndex(data, -1)
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
			DetectorType: detectors.Honeycomb,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := verifyToken(ctx, token)
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
	return verifyToken(ctx, secret)
}

func verifyToken(ctx context.Context, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/1/auth", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Honeycomb-Team", token)

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
