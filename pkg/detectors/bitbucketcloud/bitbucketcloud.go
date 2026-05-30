// Package bitbucketcloud detects Bitbucket Cloud repository / workspace /
// project access tokens (`ATCTT3xFfGF0…` and the legacy 32-char base62 app
// passwords) and verifies them as Bearer credentials against /2.0/user.
//
// Verification path is Bearer-only — the legacy "app password" model needs
// Basic auth with the username, which we don't reliably extract from the
// chunk. New repo/workspace access tokens authenticate as Bearer cleanly,
// so they're the verifiable path. App-password candidates (32-char base62
// near a "bitbucket" keyword) still surface as unverified findings so
// operators can rotate.
package bitbucketcloud

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.bitbucket.org"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Two recognised shapes:
//  1. ATCTT3xFfGF0… — Bitbucket repo/workspace/project access token. Atlassian
//     issues these with a fixed "ATCTT3xFfGF0" prefix and ~152 chars of
//     base64url payload.
//  2. 32-char base62 — legacy app password / API token. Generic shape, so we
//     gate on the "bitbucket" keyword window.
var (
	tokenRe  = regexp.MustCompile(`\b(ATCTT3xFfGF0[A-Za-z0-9_=+/-]{60,200})\b`)
	legacyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)
)

var contextKeywords = []string{"bitbucket", "bitbucket_token", "bitbucket_app_password"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BitbucketCloud }

func (Scanner) Keywords() []string { return []string{"bitbucket", "ATCTT3xFfGF0"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	// Modern access tokens: prefix is distinctive enough to skip the keyword gate.
	for _, m := range tokenRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BitbucketCloud,
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

	// Legacy 32-char tokens require keyword co-occurrence.
	legacyHits := legacyRe.FindAllSubmatchIndex(data, -1)
	if len(legacyHits) > 0 {
		lower := strings.ToLower(string(data))
		for _, h := range legacyHits {
			token := string(data[h[2]:h[3]])
			if _, dup := seen[token]; dup {
				continue
			}
			if !nearKeyword(lower, h[2], h[3]) {
				continue
			}
			seen[token] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.BitbucketCloud,
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/2.0/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
