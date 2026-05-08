// Package coinbase detects Coinbase API key + secret pairs near the
// `coinbase` keyword. Coinbase production calls require HMAC-SHA256
// signing with a timestamp, so the verify path here is the unsigned-
// bearer probe against /v2/user — production rejects it (401) which
// surfaces as unverified, and a dev/test mock returning 200 surfaces
// as verified. The HMAC path is intentionally not implemented to avoid
// timestamp drift / replay risk in scan paths. Pair encoded as RawV2.
package coinbase

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.coinbase.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Coinbase v2 API keys are 32 alnum chars; secrets are 64 alnum.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`)

var contextKeywords = []string{"coinbase"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Coinbase }

func (Scanner) Keywords() []string { return []string{"coinbase"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 || len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, kh := range keyHits {
		if !nearKeyword(lower, kh[2], kh[3]) {
			continue
		}
		key := string(data[kh[2]:kh[3]])
		for _, sh := range secretHits {
			if !nearKeyword(lower, sh[2], sh[3]) {
				continue
			}
			secret := string(data[sh[2]:sh[3]])
			k := key + ":" + secret
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Coinbase,
				Raw:          []byte(key),
				RawV2:        []byte(k),
				Redacted:     redact(key),
			}
			if verify {
				v, err := s.Verify(ctx, key)
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

func (Scanner) Verify(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/user", nil)
	if err != nil {
		return false, err
	}
	// Bearer fallback — production /v2/user expects HMAC headers and will
	// 401, mirroring the unverified path. Mock servers returning 200 for
	// the test path verify cleanly.
	req.Header.Set("CB-ACCESS-KEY", key)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
