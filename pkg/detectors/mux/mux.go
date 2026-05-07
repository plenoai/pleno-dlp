// Package mux detects Mux access token id + secret key pairs. Mux issues an
// access token id (UUID) plus a base64-encoded secret. Both halves co-occur
// near the `mux` keyword window. Verified via /video/v1/assets on
// api.mux.com using HTTP Basic auth (token id as username, secret as
// password) — read-only.
package mux

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mux.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	tokenIDRe = regexp.MustCompile(`(?i)mux[_\.\-]?(?:token[_\.\-]?id|access[_\.\-]?token[_\.\-]?id|id)\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`)
	secretRe  = regexp.MustCompile(`(?i)mux[_\.\-]?(?:token[_\.\-]?secret|secret[_\.\-]?key|secret)\s*[:=]\s*["']?([A-Za-z0-9+/=_\-]{50,200})["']?`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mux }

func (Scanner) Keywords() []string { return []string{"mux"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ids := tokenIDRe.FindAllSubmatch(data, -1)
	secrets := secretRe.FindAllSubmatch(data, -1)
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		tid := string(id[1])
		for _, sec := range secrets {
			tsec := string(sec[1])
			pair := tid + ":" + tsec
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Mux,
				Raw:          []byte(tid),
				RawV2:        []byte(tsec),
				Redacted:     redact(tid),
			}
			if verify {
				v, err := s.verifyPair(ctx, tid, tsec)
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

func (Scanner) verifyPair(ctx context.Context, tid, tsec string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/video/v1/assets?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(tid, tsec)
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
