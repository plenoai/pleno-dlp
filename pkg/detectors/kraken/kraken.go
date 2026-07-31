// Package kraken detects Kraken exchange API key + secret pairs near the
// `kraken` keyword. Verification signs a read-only GetApiKeyInfo request with
// both credential parts and requires an identity-matching Kraken JSON response.
package kraken

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.kraken.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// Kraken API keys are 56 base64-ish chars; secrets are 88 base64 chars.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9+/]{56})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9+/]{86,88}={0,2})`)

var contextKeywords = []string{"kraken"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Kraken }

func (Scanner) Keywords() []string { return []string{"kraken"} }

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
			if secret == key {
				continue
			}
			k := key + ":" + secret
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Kraken,
				Raw:          []byte(key),
				RawV2:        []byte(k),
				Redacted:     redact(key),
			}
			if verify {
				v, err := s.Verify(ctx, k)
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	key, privateSecret, ok := strings.Cut(secret, ":")
	if !ok || key == "" || privateSecret == "" {
		return false, fmt.Errorf("kraken verify: malformed credential pair")
	}
	decodedSecret, err := base64.StdEncoding.DecodeString(privateSecret)
	if err != nil {
		return false, fmt.Errorf("kraken verify: decode private secret: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// https://docs.kraken.com/api/docs/rest-api/get-api-key-info/
	// GetApiKeyInfo is read-only and requires no API-key permissions. Its
	// response includes the authenticated key, which lets us prove the exact
	// candidate pair rather than treating generic transport success as valid.
	const requestPath = "/0/private/GetApiKeyInfo"
	nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
	form := url.Values{"nonce": {nonce}}
	encodedForm := form.Encode()
	digest := sha256.Sum256([]byte(nonce + encodedForm))
	mac := hmac.New(sha512.New, decodedSecret)
	_, _ = mac.Write(append([]byte(requestPath), digest[:]...))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(apiBase, "/")+requestPath,
		strings.NewReader(encodedForm),
	)
	if err != nil {
		return false, err
	}
	req.Header.Set("API-Key", key)
	req.Header.Set("API-Sign", signature)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := httpClient.Do(req)
	if err != nil {
		return detectors.ClassifyVerifyHTTP(nil, err, nil, nil)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return detectors.ClassifyVerifyHTTP(
			resp,
			nil,
			nil,
			[]int{http.StatusUnauthorized},
		)
	}

	var body struct {
		Error  []string `json:"error"`
		Result *struct {
			APIKey string `json:"apiKey"`
		} `json:"result"`
	}
	if err := detectors.DecodeVerifyJSON(resp.Body, 64<<10, &body); err != nil {
		return false, fmt.Errorf("kraken verify: decode response: %w", err)
	}
	if len(body.Error) == 0 {
		if body.Result == nil || body.Result.APIKey == "" {
			return false, fmt.Errorf("kraken verify: success response lacks authenticated key")
		}
		if body.Result.APIKey != key {
			return false, fmt.Errorf("kraken verify: response identity mismatch")
		}
		return true, nil
	}

	for _, apiError := range body.Error {
		lower := strings.ToLower(apiError)
		if strings.Contains(lower, "invalid key") ||
			strings.Contains(lower, "invalid signature") {
			return false, nil
		}
		if strings.Contains(lower, "rate limit") ||
			strings.Contains(lower, "throttl") ||
			strings.Contains(lower, "temporar") ||
			strings.Contains(lower, "unavailable") {
			return false, fmt.Errorf("kraken verify: transient API rejection")
		}
	}
	return false, fmt.Errorf("kraken verify: ambiguous API rejection")
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
