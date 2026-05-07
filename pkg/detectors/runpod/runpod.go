// Package runpod detects RunPod API keys (UUID near `runpod`) and verifies
// them against the GraphQL endpoint with a `{ myself { id } }` probe.
//
// RunPod tokens are UUIDs; co-occurrence with `runpod` is mandatory because
// raw UUIDs are far too noisy to surface alone.
package runpod

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.runpod.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// UUID v4 shape, optionally prefixed with `RUNPOD_API_KEY_` style; we
// match the bare UUID and gate by keyword.
var keyRe = regexp.MustCompile(`\b([A-Z0-9]{8}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{20,32})\b`)

// RunPod's older keys also appear as 32-char base64url; capture both shapes.
var altRe = regexp.MustCompile(`\b([A-Z0-9]{40,64})\b`)

var contextKeywords = []string{"runpod", "runpod_api", "runpod_key"}

var probeBody = []byte(`{"query":"{ myself { id } }"}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RunPod }

func (Scanner) Keywords() []string { return []string{"runpod"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAllSubmatchIndex(data, -1)
	matches = append(matches, altRe.FindAllSubmatchIndex(data, -1)...)
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
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.RunPod,
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
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/graphql", bytes.NewReader(probeBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

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
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
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
