// Package walmart detects Walmart Marketplace API client identifiers
// (UUID) + secret pair near the walmart keyword. Unverified-by-design
// — Walmart's marketplace gateway requires RSA-PKCS8 signing of a
// per-request nonce, so a bearer probe always 401s without the
// signed-header dance. Verify only fires when an apiBase override is
// supplied for tests. RawV2 carries the secret half.
package walmart

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://marketplace.walmartapis.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var idRe = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9+/=_-]{40,300})\b`)

var contextKeywords = []string{"walmart"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Walmart }

func (Scanner) Keywords() []string { return []string{"walmart"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := idRe.FindAllSubmatchIndex(data, -1)
	secHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 || len(secHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var clientID string
	for _, h := range idHits {
		if nearKeyword(lower, h[2], h[3]) {
			clientID = string(data[h[2]:h[3]])
			break
		}
	}
	if clientID == "" {
		return nil, nil
	}
	var secret string
	for _, h := range secHits {
		token := string(data[h[2]:h[3]])
		if token == clientID {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		secret = token
		break
	}
	if secret == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Walmart,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientID + ":" + secret),
		Redacted:     redact(clientID),
	}
	if verify {
		v, err := s.Verify(ctx, clientID+":"+secret)
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
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v3/items", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("WM_SEC.ACCESS_TOKEN", sec)
	req.Header.Set("WM_CONSUMER.ID", id)
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
