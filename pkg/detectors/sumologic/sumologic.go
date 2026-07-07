// Package sumologic detects Sumo Logic access ID + access key pairs and
// verifies them via /api/v1/users/me with HTTP Basic auth.
//
// Sumo Logic access credentials grant programmatic access to the entire log
// archive — leaking a pair is graded SeverityCritical regardless of verify
// status.
package sumologic

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sumologic.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Access IDs are 14 chars with a documented `su` prefix
	// (upstream trufflehog: `su[A-Za-z0-9]{12}`). The prefix is the
	// distinguishing anchor, so no entropy floor is needed on the ID.
	idRe = regexp.MustCompile(`\b(su[A-Za-z0-9]{12})\b`)
	// Access keys are 64 base62 chars with no prefix
	// (upstream trufflehog: `[A-Za-z0-9]{64}`). A bare fixed-length
	// alnum run is FP-prone, so the candidate must additionally clear an
	// entropy floor (keyMinEntropy) before it is accepted as a key.
	keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{64})\b`)
)

// keyMinEntropy rejects low-information 64-char runs that clear the
// alnum regex but lack key-grade randomness. 3.5 bits/char suits the
// high-variety base62 access-key charset per docs/detector-key-formats.md.
const keyMinEntropy = 3.5

// armRe is the assignment-style Sumo Logic reference that must appear within
// the proximity window. A bare `strings.Contains(window, "sumo")` over a wide
// radius matched unrelated prose and script-src URLs; the arm regex requires
// the credential-assignment shape Sumo Logic configs actually use while the
// bare keyword stays in Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)sumo[_-]?(logic)?[_-]?(access[_-]?)?(id|key|token|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SumoLogic }

func (Scanner) Keywords() []string { return []string{"sumologic", "sumo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := idRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 {
		return nil, nil
	}
	keyHits := keyRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(idHits))
	seen := map[string]struct{}{}
	for _, m := range idHits {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}

		res := detectors.Result{
			DetectorType: detectors.SumoLogic,
			Raw:          []byte(id),
			Redacted:     redact(id),
			Severity:     detectors.SeverityCritical,
		}
		if key, ok := nearestKey(m[2], data, keyHits); ok {
			res.RawV2 = []byte(key)
			if verify {
				v, err := verifyPair(ctx, id, key)
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

func nearestKey(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 512
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		candidate := string(data[start:end])
		// Entropy gate: a 64-char run with sub-key randomness is a
		// placeholder/digest, not a Sumo Logic access key — skip it so it
		// neither pairs with the ID nor suppresses a real nearby key.
		if !detectors.HasMinEntropy(candidate, keyMinEntropy) {
			continue
		}
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = candidate
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, key, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, key)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, id, key string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/users/me", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, key)

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
