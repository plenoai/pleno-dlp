// Package jfrog detects JFrog Artifactory access tokens. Two shapes are
// in the wild:
//
//   - Reference tokens: base64 starting with `cmVmdGtuO` (literal
//     "reftkn:..." prefix). Stable, distinctive shape.
//   - Identifier-aware (JWT) tokens: handled by the generic JWT detector.
//
// We only own the reference-token shape here because it has a unique
// prefix that won't collide with the JWT detector. Verification probes
// /artifactory/api/system/ping with Bearer auth — the platform's
// canonical liveness endpoint that requires a valid token when the
// instance has anonymous-access disabled. Without a base URL we can't
// verify, so the public regex match alone is the unverified-by-design
// path; ExtraData captures the nearest jfrog/artifactory keyword.
package jfrog

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Reference tokens: base64 of "reftkn:01:<expiry>:<id>:<secret>" — every
// such string starts with "cmVmdGtuO". Production tokens are 200+ chars
// after the prefix; we accept 80+ to allow for future-format truncation
// while still rejecting bare "cmVmdGtuO" mentions in docs/comments.
var keyRe = regexp.MustCompile(`\b(cmVmdGtuO[A-Za-z0-9+/=_-]{80,})\b`)

// hostRe extracts a *.jfrog.io host or `/artifactory` path so we can probe.
var hostRe = regexp.MustCompile(`https?://[a-zA-Z0-9.-]+(?:\.jfrog\.io|/artifactory)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType         { return detectors.JFrog }
func (Scanner) VerificationCacheUsesFullInput() bool { return true }

func (Scanner) Keywords() []string { return []string{"cmVmdGtuO", "jfrog", "artifactory"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.JFrog,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			host := nearestHost(data, h[2])
			if host != "" {
				v, err := verifyWith(ctx, host, token)
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	host, token, ok := strings.Cut(secret, "|")
	if !ok {
		return false, nil
	}
	return verifyWith(ctx, host, token)
}

func verifyWith(ctx context.Context, host, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, host+"/artifactory/api/system/ping", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
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

func nearestHost(data []byte, pos int) string {
	const radius = 1024
	from := pos - radius
	if from < 0 {
		from = 0
	}
	to := pos + radius
	if to > len(data) {
		to = len(data)
	}
	if m := hostRe.Find(data[from:to]); m != nil {
		return string(m)
	}
	return ""
}

func redact(t string) string {
	if len(t) <= 9 {
		return t
	}
	return t[:9] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
