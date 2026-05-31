// Package backblazeb2 detects Backblaze B2 application key id + key pairs and
// verifies them live. The key id is a 25-char base64-ish string prefixed with
// "K00"; the application key itself is ~31 chars of base64 with NO "K00"
// prefix (the old regex wrongly required one). The pair authenticates against
// a single fixed global endpoint — b2_authorize_account — via HTTP Basic auth
// (base64(keyID:applicationKey)); the regional apiUrl is returned in the
// response body, not required in the request. HTTP status is a clean yes/no:
// 200 = valid, 401/403 = invalid. Co-occurrence with `b2_` / `backblaze`
// keyword is mandatory.
package backblazeb2

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// b2_authorize_account is a single fixed global endpoint. Tests override
// apiBase to point at an httptest server.
var apiBase = "https://api.backblazeb2.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

const authPath = "/b2api/v2/b2_authorize_account"

var (
	// Key ID: "K00" + 22-30 base64url-ish chars.
	keyIDRe = regexp.MustCompile(`\b(K00[A-Za-z0-9]{22,30})\b`)
	// Application key: ~31 chars of base64 (alnum, +, /), no K00 prefix.
	// Loosened from the old K00-anchored regex per real-world shape.
	keyRe = regexp.MustCompile(`\b([A-Za-z0-9+/]{27,40})\b`)
)

var contextKeywords = []string{"b2_", "backblaze", "b2_application_key", "b2_app_key", "b2_key_id"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BackblazeB2 }

func (Scanner) Keywords() []string { return []string{"b2_", "backblaze"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ids := keyIDRe.FindAllSubmatchIndex(data, -1)
	keys := keyRe.FindAllSubmatchIndex(data, -1)
	if len(ids) == 0 || len(keys) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, k := range ids {
		id := string(data[k[2]:k[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		if !nearKeyword(lower, k[2], k[3]) {
			continue
		}
		key, ok := nearestKey(k[2], data, keys, id)
		if !ok {
			continue
		}
		seen[id] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BackblazeB2,
			Raw:          []byte(id),
			RawV2:        []byte(id + ":" + key),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"key_id": id},
		}
		if verify {
			v, err := verifyPair(ctx, id, key)
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

func nearestKey(idStart int, data []byte, hits [][]int, id string) (string, bool) {
	const maxDistance = 2048
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		s := string(data[h[2]:h[3]])
		// The application key is never the key id itself. Skip the id match.
		if s == id {
			continue
		}
		dist := h[2] - idStart
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = s
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
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

// Verify expects the secret packed as "<keyID>:<applicationKey>" (the same
// shape stored in Result.RawV2). The engine-level verify path passes RawV2.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, key, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, key)
}

func splitPair(s string) (string, string, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// verifyPair calls the fixed b2_authorize_account endpoint with HTTP Basic
// auth (keyID:applicationKey). 200 => valid, 401/403 => invalid, 429/5xx =>
// transient (surfaced as VerificationErr, Verified=false).
func verifyPair(ctx context.Context, id, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+authPath, nil)
	if err != nil {
		return false, err
	}
	cred := base64.StdEncoding.EncodeToString([]byte(id + ":" + key))
	req.Header.Set("Authorization", "Basic "+cred)

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr,
		[]int{http.StatusOK},
		[]int{http.StatusUnauthorized, http.StatusForbidden})
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
