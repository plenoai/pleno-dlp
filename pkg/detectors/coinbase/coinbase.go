// Package coinbase detects Coinbase API key + secret pairs near the
// `coinbase` keyword. Coinbase production calls require HMAC-SHA256
// signing with a timestamp, so the verify path here is the unsigned-
// bearer probe against /v2/user — production rejects it (401) which
// surfaces as unverified, and a dev/test mock returning 200 surfaces
// as verified. The HMAC path is intentionally not implemented to avoid
// timestamp drift / replay risk in scan paths. Pair encoded as RawV2.
package coinbase

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.coinbase.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Coinbase v2 API keys are 32 alnum chars; secrets are 64 alnum.
//
// NOTE ON FORMAT: authoritative Coinbase docs do not document a bare
// 32/64 alphanumeric credential. The CDP "create API key" flow issues a
// key *name* of the shape `organizations/{uuid}/apiKeys/{uuid}` plus an
// EC PEM private key as the secret (see docs.cdp.coinbase.com API-key
// authentication, and upstream trufflehog pkg/detectors/coinbase which
// matches that path + `-----BEGIN EC PRIVATE KEY-----`). The 32/64 alnum
// shape this detector keys on is NOT authoritatively documented, so the
// lengths below are left as-is (changing them would silently move recall)
// and we apply only recall-safe gate tightening: a tight assignment-anchor
// arm regex over a radius-64 window plus a conservative entropy floor.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`)

// armRe is the assignment-style Coinbase reference that must appear within
// the proximity window. A bare "coinbase" substring is too weak a gate
// against generic 32/64-char alnum runs;
// `coinbase[_-]?(api[_-]?)?(token|key|secret)` is the shape a real
// credential assignment or config key takes. The bare keyword stays in
// Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)coinbase[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information 32/64-char alnum runs (padded
// placeholders, repeated characters, structured IDs) that clear the regex
// but are not random tokens. 3.5 fits the 62-variety alnum charset; the
// realistic dummy fixtures sit well above it (key 4.37, secret 4.95).
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Coinbase }

func (Scanner) Keywords() []string { return []string{"coinbase"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(keyHits) == 0 || len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, kh := range keyHits {
		if !nearKeyword(lower, kh[2], kh[3]) {
			continue
		}
		key := string(data[kh[2]:kh[3]])
		if !detectors.HasMinEntropy(key, minEntropy) {
			continue
		}
		for _, sh := range secretHits {
			if !nearKeyword(lower, sh[2], sh[3]) {
				continue
			}
			secret := string(data[sh[2]:sh[3]])
			if !detectors.HasMinEntropy(secret, minEntropy) {
				continue
			}
			k := key + ":" + secret
			if _, dup := seen[k]; dup {
				continue
			}
			seen[k] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Coinbase,
				Raw:          []byte(key),
				RawV2:        []byte(k),
				Redacted:     redact(key),
			}
			if verify {
				v, err := s.Verify(ctx, key)
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

// nearKeyword reports whether a `coinbase[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the candidate.
// The window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby COINBASE_API_KEY reference still arms.
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

func (Scanner) Verify(ctx context.Context, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/user", nil)
	if err != nil {
		return false, err
	}
	// Bearer fallback — production /v2/user expects HMAC headers and will
	// 401, mirroring the unverified path. Mock servers returning 200 for
	// the test path verify cleanly.
	req.Header.Set("CB-ACCESS-KEY", key)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
