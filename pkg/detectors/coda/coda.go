// Package coda detects Coda API tokens (40-char alnum co-occurring with
// `coda`) and verifies them against /v1/whoami using Bearer auth.
//
// Coda tokens grant the issuing user's full doc-platform scope. The
// 40-char alnum shape is too generic on its own, so a co-occurring
// `coda` keyword is mandatory.
package coda

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://coda.io"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// Coda tokens are 36-char UUID-with-hyphens or 40-char alnum.
var tokenRe = sync.OnceValue(func() *detectors.Regexp { return detectors.MustCompile(`\b([A-Za-z0-9_-]{36,48})\b`) })

var contextKeywords = []string{"coda", "coda_token", "coda_api", "coda.io"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Coda }

func (Scanner) Keywords() []string { return []string{"coda"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe().FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if inLockChecksum(data, m[2]) {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Coda,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return detectors.SafeResults(out), nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/apis/v1/whoami", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
		for off := 0; ; {
			i := strings.Index(window[off:], kw)
			if i < 0 {
				break
			}
			i += off
			// A keyword embedded in a longer alnum run (e.g. "cOda" inside a
			// base64 checksum) is not context.
			if i == 0 || !isAlnum(window[i-1]) {
				return true
			}
			off = i + 1
		}
	}
	return false
}

// inLockChecksum reports whether the candidate at start lies inside a
// Terraform lock file checksum value (`h1:` base64 SHA-256 or `zh:` hex).
func inLockChecksum(data []byte, start int) bool {
	i := start
	for i > 0 && isBase64(data[i-1]) {
		i--
	}
	if i < 3 {
		return false
	}
	p := strings.ToLower(string(data[i-3 : i]))
	return p == "h1:" || p == "zh:"
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func isBase64(c byte) bool {
	return isAlnum(c) || c == '+' || c == '/' || c == '=' || c == '_' || c == '-'
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
