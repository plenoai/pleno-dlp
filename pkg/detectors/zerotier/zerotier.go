// Package zerotier detects ZeroTier Central API tokens. The provider's
// OpenAPI-generated client documents the token as a "Random 32 character
// token" of "hex encoded random bytes"
// (https://docs.rs/zerotier-central-api/1.0.0/src/zerotier_central_api/models/random_token.rs.html),
// matching trufflehog upstream's `\b([0-9a-zA-Z]{32})\b`. The length (32) is
// authoritative; the charset is kept broad-alnum to preserve recall against
// upper/mixed-case variants. Because the bare 32-char shape is universal, two
// gates suppress false positives: an assignment-style `zerotier ...
// token/key/secret` arm regex within a 64-byte radius, and a hex-appropriate
// Shannon entropy floor of 3.0 bits/char (hex caps ~3.6, so 3.5 would
// over-cull). Verified via /api/v1/status on my.zerotier.com with the
// Authorization Bearer header.
package zerotier

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://my.zerotier.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe matches the documented 32-character token. Charset stays broad-alnum
// (rather than strict hex) so mixed-case fixtures and any non-lowercase
// provider variants still detect; the entropy floor culls low-variety runs.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// armRe is the assignment-style ZeroTier reference that must appear within the
// nearKeyword window for a candidate to arm. Replaces the prior bare
// strings.Contains("zerotier") gate, which fired on any chunk merely mentioning
// the word near a generic 32-char run.
var armRe = regexp.MustCompile(`(?i)zerotier[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is a conservative, hex-appropriate Shannon floor. A 32-char hex
// token entropy bottoms out around 4.0 bits/char, so 3.0 preserves recall while
// rejecting padded placeholders and repeated-character runs.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ZeroTier }

func (Scanner) Keywords() []string { return []string{"zerotier"} }

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
		// Entropy gate: structured/low-information 32-char runs (a padded
		// placeholder or repeated characters) clear the alnum regex but are not
		// random tokens — reject them even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ZeroTier,
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
	return out, nil
}

// nearKeyword arms the candidate only when an assignment-style ZeroTier
// reference (matched by armRe) sits within `radius` bytes of the token. A
// stray `zerotier` mention elsewhere in a large chunk no longer arms a generic
// 32-char run.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/status", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
