// Package pusherchannels detects Pusher Channels app secrets — a 20-character
// alphanumeric secret used together with an app id and key for HMAC signing
// the realtime API. Verified by signing an `auth_version=1.0` request to
// /apps/<app_id>/events would require the app id; without it, surfaced as
// unverified-by-design (HMAC scheme, write API only).
package pusherchannels

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is here for completeness; verification is unverified-by-design
// because Pusher requires app_id + key + secret + cluster, not just the
// secret. Hosts are <cluster>.pusher.com.
var apiBase = "https://api.pusher.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Pusher Channels app_secret is documented as 20 char alphanumeric. Generic
// shape — keyword gate required.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20})\b`)

var contextKeywords = []string{"pusher_app_secret", "pusher_secret", "pusher_channels", "pusherapp"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PusherChannels }

func (Scanner) Keywords() []string { return []string{"pusher"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.PusherChannels,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		// Unverified by design: HMAC signing scheme requires app_id + cluster
		// not in the chunk.
		_ = verify
		out = append(out, res)
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

// Verify probes the user-overridable apiBase. Real verification requires
// HMAC signing with app_id + key + cluster; this stub is here for the
// Verifier-interface contract and for tests.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/apps/_/info?auth_key="+secret, nil)
	if err != nil {
		return false, err
	}
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
