// Package plaid detects Plaid client_id (24-hex) + secret (30-hex) pairs and
// verifies them by POSTing to /categories/get, the cheapest sandbox-safe
// endpoint that authenticates the pair without side effects.
//
// Plaid credentials grant programmatic access to linked bank accounts, so a
// leaked pair is graded SeverityCritical regardless of verify status.
//
// Both halves are pure hex of distinct lengths, so we can disambiguate by
// shape: 24-char hex = client_id, 30-char hex = secret. The plaid keyword is
// still required because hex-shaped strings are widespread.
package plaid

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://production.plaid.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	idRe     = regexp.MustCompile(`\b([a-f0-9]{24})\b`)
	secretRe = regexp.MustCompile(`\b([a-f0-9]{30})\b`)
)

var contextKeywords = []string{"plaid", "plaid_client_id", "plaid_secret"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Plaid }

func (Scanner) Keywords() []string { return []string{"plaid"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := idRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 {
		return nil, nil
	}
	secHits := secretRe.FindAllSubmatchIndex(data, -1)

	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idHits))
	seen := map[string]struct{}{}
	for _, m := range idHits {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}

		res := detectors.Result{
			DetectorType: detectors.Plaid,
			Raw:          []byte(id),
			Redacted:     redact(id),
			Severity:     detectors.SeverityCritical,
		}
		sec, ok := nearestSecret(m[2], data, secHits)
		if ok {
			res.RawV2 = []byte(sec)
			if verify {
				v, err := verifyPair(ctx, id, sec)
				res.Verified = v
				res.VerificationErr = err
			}
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

func nearestSecret(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, id, sec string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(map[string]string{
		"client_id": id,
		"secret":    sec,
	})
	if err != nil {
		return false, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/categories/get", bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		// 400 from /categories/get with INVALID_API_KEYS body is the failure
		// shape. We don't read the body — distinguishing 400-INVALID-KEYS
		// from 400-other is unnecessary; either way the credentials are not
		// usable as-is.
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
