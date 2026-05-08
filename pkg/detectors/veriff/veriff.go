// Package veriff detects Veriff KYC API key (UUID) + shared-secret pair
// near the `veriff` keyword. Verified via /v1/sessions on
// stationapi.veriff.com with the X-AUTH-CLIENT header. RawV2 carries
// the shared secret per the trufflehog convention.
package veriff

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://stationapi.veriff.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var idRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
var secretRe = regexp.MustCompile(`\b([a-f0-9]{64})\b`)

var contextKeywords = []string{"veriff"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Veriff }

func (Scanner) Keywords() []string { return []string{"veriff"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := idRe.FindAllSubmatchIndex(data, -1)
	secHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 || len(secHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var apiKey, shared string
	for _, h := range idHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		apiKey = string(data[h[2]:h[3]])
		break
	}
	if apiKey == "" {
		return nil, nil
	}
	for _, h := range secHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		shared = string(data[h[2]:h[3]])
		break
	}
	if shared == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Veriff,
		Raw:          []byte(apiKey),
		RawV2:        []byte(apiKey + ":" + shared),
		Redacted:     redact(apiKey),
	}
	if verify {
		v, err := s.Verify(ctx, apiKey+":"+shared)
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
	apiKey := parts[0]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/sessions", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-AUTH-CLIENT", apiKey)
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
