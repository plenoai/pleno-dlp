// Package zoom detects Zoom OAuth client_id + client_secret pairs and
// verifies them by exchanging the pair for an access token via the
// /oauth/token endpoint with HTTP Basic auth.
//
// Zoom OAuth credentials grant programmatic access to the entire account
// (depending on installed scopes), so leaked pairs are graded
// SeverityCritical regardless of verify status.
package zoom

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.zoom.us"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Zoom client_id is 22 base64url chars; client_secret is 32 base64url chars.
// Both sit alongside the `zoom` keyword in source.
var (
	idRe     = regexp.MustCompile(`\b([A-Za-z0-9_-]{22})\b`)
	secretRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{32})\b`)
)

var contextKeywords = []string{"zoom", "zoom_client_id", "zoom_client_secret", "zoom_oauth"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Zoom }

func (Scanner) Keywords() []string { return []string{"zoom"} }

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

		// 22-char hits also match inside 32-char hits (regex with \b
		// anchors would not, but nested overlap can still happen if the
		// surrounding bytes form a word boundary). Skip ids that overlap
		// any 32-char run.
		if overlapsRun(m[2], m[3], secHits) {
			continue
		}

		res := detectors.Result{
			DetectorType: detectors.Zoom,
			Raw:          []byte(id),
			Redacted:     redact(id),
			Severity:     detectors.SeverityCritical,
		}
		if sec, ok := nearestSecret(m[2], data, secHits, m); ok {
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

func overlapsRun(start, end int, runs [][]int) bool {
	for _, r := range runs {
		if r[2] <= start && start < r[3] {
			return true
		}
		if start <= r[2] && r[2] < end {
			return true
		}
	}
	return false
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

func nearestSecret(idStart int, data []byte, hits [][]int, idMatch []int) (string, bool) {
	const maxDistance = 512
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		// Skip the same span if it happened to also match the secret regex.
		if h[2] == idMatch[2] && h[3] == idMatch[3] {
			continue
		}
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

	body := strings.NewReader(url.Values{
		"grant_type": {"client_credentials"},
		"account_id": {""}, // server-to-server flow needs account_id, but pure client_credentials still 401s on a bad pair before the account check
	}.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/oauth/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
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
