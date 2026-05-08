// Package livekit detects LiveKit realtime audio/video API key + secret
// pairs near the `livekit` keyword. Unverified by default — LiveKit
// servers are typically self-hosted or per-project (`<project>.livekit.cloud`),
// no canonical host. Verification fires only when an apiBase override is
// supplied.
package livekit

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b(API[A-Za-z0-9]{10,16})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,48})\b`)

var contextKeywords = []string{"livekit"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LiveKit }

func (Scanner) Keywords() []string { return []string{"livekit"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	secretHits := secretRe.FindAllSubmatch(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, h := range keyHits {
		key := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		for _, sh := range secretHits {
			secret := string(sh[1])
			if secret == key {
				continue
			}
			pair := key + ":" + secret
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.LiveKit,
				Raw:          []byte(key),
				RawV2:        []byte(pair),
				Redacted:     redact(key),
			}
			if verify && apiBase != "" {
				v, err := s.verifyPair(ctx, key, secret)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, key, _ string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/twirp/livekit.RoomService/ListRooms", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+key)
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
