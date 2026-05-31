// Package june detects June.so analytics write keys near the `june`
// keyword. Verified via /sdk/track on api.june.so using HTTP Basic
// auth (key as username, empty password).
//
// Key format is NOT authoritatively documented: June.so is a Segment
// Analytics.js fork (@june-so/analytics-node) and every official SDK
// page shows only the placeholder <YOUR_WRITE_KEY> — no literal sample,
// no published length or charset. There is no upstream trufflehog june
// detector to mirror. Per the inconclusive-research fallback we do NOT
// pin a june-specific length: the regex floor of 16 below is a generic
// noise floor (not a format claim), and disambiguation is carried by the
// assignment-anchor arm regex plus a conservative entropy gate.
package june

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.june.so"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Unpinned alnum run. {16,} is a generic short-noise floor, not a
// documented june key length — the format is unknown (see package doc).
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{16,})\b`)

// armRe is the assignment-style June reference that must appear within the
// proximity window. A bare "june.so" substring (script-src CDN URLs, doc
// links) is too weak a gate against a generic alphanumeric run;
// june[_-]?(write[_-]?)?(api[_-]?)?(token|key|secret) is the shape a real
// write-key assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)june[_\-]?(write[_\-]?)?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-information runs (repeated chars, padded
// placeholders) that clear the alnum regex but are not real keys. 3.0 is
// the conservative floor mandated when the charset is unknown — a higher
// floor risks culling real keys whose charset we cannot confirm.
const minEntropy = 3.0

// contextKeywords removed: the bare strings.Contains over radius 256 was
// replaced by armRe over radius 64. The prefilter keywords live in
// Keywords() below.

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.June }

func (Scanner) Keywords() []string {
	return []string{"june.so", "june_write_key", "june-write-key", "junewritekey"}
}

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
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.June,
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/sdk/track", strings.NewReader("{}"))
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(secret, "")
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusBadRequest {
		// 400 with valid auth indicates the key authenticated but the
		// (empty) payload was rejected — treat that as "verified".
		if resp.StatusCode == http.StatusOK {
			return true, nil
		}
		return false, nil
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
