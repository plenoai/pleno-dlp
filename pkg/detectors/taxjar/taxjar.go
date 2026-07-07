// Package taxjar detects TaxJar API tokens. Tokens are 32-char lowercase
// alphanumeric (`[a-z0-9]{32}`, hex-like, no distinguishing prefix) per the
// upstream trufflehog detector, which is the authoritative format source
// (the public TaxJar auth docs do not pin a format). A bare 32-char hex run
// hits constantly in real codebases (git object ids, md5 digests, nonces), so
// the bare-substring gate is replaced with a `taxjar[_-]?(api[_-]?)?(token|
// key|secret)` arm regex within a tight 64-byte window AND a conservative
// Shannon-entropy floor. Verified via /v2/categories on api.taxjar.com with
// Bearer auth. Example token shape: <32-LOWER-ALNUM-TOKEN>.
package taxjar

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.taxjar.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32 lowercase alphanumeric per upstream trufflehog (`[a-z0-9]{32}`). No
// prefix to anchor on, so the arm regex + entropy floor carry the
// false-positive load.
var tokenRe = regexp.MustCompile(`\b([a-z0-9]{32})\b`)

// armRe is the assignment-style TaxJar reference that must appear within the
// proximity window. A bare "taxjar" substring (dependency names, doc URLs,
// comments) is too weak; "taxjar_api_token" / "taxjar-key" / "taxjartoken"
// is the shape a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)taxjar[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-variety 32-char runs that clear the lowercase-alnum
// regex but are not random tokens. The charset is hex-like (low variety, caps
// near ~3.6 bits/char for pure hex), so 3.0 is the recall-safe floor — 3.5
// would over-cull legitimate hex-shaped tokens.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TaxJar }

func (Scanner) Keywords() []string { return []string{"taxjar"} }

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
		// Entropy gate: structured/low-information 32-char runs are rejected
		// even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.TaxJar,
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

// nearKeyword reports whether a `taxjar[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions so a token defined alongside a nearby
// TAXJAR_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/categories", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Accept", "application/json")
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
