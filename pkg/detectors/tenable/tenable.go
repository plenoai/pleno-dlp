// Package tenable detects Tenable.io / Tenable.sc API key+secret pairs.
// Tenable uses an `accessKey=<64-hex>; secretKey=<64-hex>` API custom-key
// scheme. Both halves co-occur near the `tenable` keyword window. Verified
// via /session on cloud.tenable.com using the X-ApiKeys header.
package tenable

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://cloud.tenable.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	accessRe = regexp.MustCompile(`(?i)access[_\.\-]?key\s*[:=]\s*["']?([a-f0-9]{64})["']?`)
	secretRe = regexp.MustCompile(`(?i)secret[_\.\-]?key\s*[:=]\s*["']?([a-f0-9]{64})["']?`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Tenable }

func (Scanner) Keywords() []string { return []string{"tenable"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !strings.Contains(strings.ToLower(string(data)), "tenable") {
		return nil, nil
	}
	access := accessRe.FindAllSubmatch(data, -1)
	secrets := secretRe.FindAllSubmatch(data, -1)
	if len(access) == 0 || len(secrets) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(access))
	seen := map[string]struct{}{}
	for _, a := range access {
		akey := string(a[1])
		for _, sec := range secrets {
			skey := string(sec[1])
			pair := akey + ":" + skey
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Tenable,
				Raw:          []byte(akey),
				RawV2:        []byte(skey),
				Redacted:     redact(akey),
			}
			if verify {
				v, err := s.verifyPair(ctx, akey, skey)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, access, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/session", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-ApiKeys", "accessKey="+access+"; secretKey="+secret)
	req.Header.Set("Accept", "application/json")

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
