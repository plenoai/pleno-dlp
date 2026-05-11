// Package branchio detects Branch.io key + secret pairs near the `branch_io`
// keyword. Branch keys use the `key_live_` / `key_test_` prefix (32 base62
// chars after); the matching secret uses the `secret_live_` / `secret_test_`
// prefix. Raw carries the key, RawV2 carries the paired secret. Branch
// requires both halves for any meaningful auth, so we surface paired hits
// only. Verified via /v1/app/<key> on api2.branch.io with branch_secret
// parameter.
package branchio

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api2.branch.io"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b(key_(?:live|test)_[A-Za-z0-9]{32,})\b`)
var secretRe = regexp.MustCompile(`\b(secret_(?:live|test)_[A-Za-z0-9]{32,})\b`)

// contextKeywords intentionally drops the bare "branch" keyword: it
// matches git terminology (`branched`, `branching`, `branchless`) and
// the rest of the JavaScript ecosystem. The token regex
// (`key_live_*` / `secret_live_*`) is well-prefixed so a tight
// keyword set adds robustness without losing coverage.
var contextKeywords = []string{"branch_io", "branch.io", "branch_key", "branchsdk", "branchapi", "branchmetrics"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BranchIO }

// Keywords are scanned by the engine prefilter; we drop the bare
// "branch" (collides with git terminology) and rely on the
// well-prefixed `key_live_` / `key_test_` tokens themselves plus
// `branch.io` to identify Branch.io chunks.
func (Scanner) Keywords() []string {
	return []string{"key_live_", "key_test_", "branch.io", "branch_io", "branchsdk", "branchmetrics"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, kh := range keyHits {
		key := string(data[kh[2]:kh[3]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, kh[2], kh[3]) {
			continue
		}
		secret := nearestSecret(data, kh[2], kh[3])
		if secret == "" {
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BranchIO,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(key),
		}
		if verify {
			v, err := s.Verify(ctx, key+"|"+secret)
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

func nearestSecret(data []byte, start, end int) string {
	const radius = 512
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(data) {
		to = len(data)
	}
	if m := secretRe.FindSubmatchIndex(data[from:to]); m != nil {
		return string(data[from+m[2] : from+m[3]])
	}
	return ""
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

// Verify accepts the combined `key|secret` pair (Branch's API expects both).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, "|", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	q := url.Values{}
	q.Set("branch_key", key)
	q.Set("branch_secret", sec)
	endpoint := strings.TrimRight(apiBase, "/") + "/v1/app/" + key + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
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
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
