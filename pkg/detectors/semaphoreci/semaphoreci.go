// Package semaphoreci detects Semaphore CI 2.0 API tokens. Tokens are passed
// as `Authorization: Token <TOKEN>` against `<org>.semaphoreci.com/api/v1alpha`
// (official docs: https://docs.semaphore.io/reference/api). The official docs
// do NOT publish the token prefix, length, or charset — no authoritative
// format exists — so the original bare `[A-Za-z0-9]{40,80}` shape near a
// `semaphore` substring over a 256-byte radius was a heavy false-positive
// risk (commit SHAs, nonces, base64 blobs near any "semaphore" mention — e.g.
// the Go sync.Semaphore type or the semaphore-job CLI library).
//
// Because the format is unverifiable, we apply only recall-safe gate
// tightening: keep the documented-unknown length range untouched, shrink the
// proximity radius 256->64, replace the bare-substring gate with an
// assignment-anchor arm regex (`semaphore[_-]?(api[_-]?)?(token|key|secret)`),
// and add a conservative Shannon-entropy floor (3.0) to drop low-information
// runs. We do NOT pin a length — no source documents one, and an over-tight
// length silently destroys recall.
//
// Verified via /api/v1alpha/projects on the per-org host; apiBase override
// required for verification — this detector ships unverified-by-default
// because the org host is not in the chunk.
package semaphoreci

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "" // per-org host (`<org>.semaphoreci.com`); empty = unverified.

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe stays at the original {40,80} alphanumeric range. The official docs
// do not document a length or charset, so narrowing this would risk recall;
// the arm regex and entropy floor carry the false-positive load instead.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Semaphore reference that must appear within the
// proximity window. A bare "semaphore" substring (the Go sync.Semaphore type,
// the semaphore CLI library, generic mutex commentary) is too weak;
// `semaphore_token` / `semaphore-api-key` / `semaphoreci secret` is the shape a
// real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)semaphore(ci)?[_\- ]?(api[_\- ]?)?(token|key|secret)`)

// minEntropy rejects low-information 40-80 char runs that clear the alnum
// regex but are not random tokens (padded identifiers, repeated structure).
// 3.0 is conservative — a real ~40-char token clears it comfortably — chosen
// because no source documents the charset (a 3.5 floor could over-cull).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SemaphoreCI }

func (Scanner) Keywords() []string { return []string{"semaphore"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// A `semaphore[_-]?(api[_-]?)?(token|key|secret)` reference within a
		// tight window is mandatory — 40-80 char alphanumerics are common
		// (hashes, base64 blobs, ids) and a bare "semaphore" mention is weak.
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information runs are rejected even
		// when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.SemaphoreCI,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether a semaphore token-assignment reference appears
// within a tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a token defined alongside a
// nearby SEMAPHORE_API_TOKEN reference still arms.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1alpha/projects", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token "+secret)
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
