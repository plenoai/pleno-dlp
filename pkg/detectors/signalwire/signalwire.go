// Package signalwire detects SignalWire Project ID + API token pairs near
// the `signalwire` keyword. Verified via /api/laml/2010-04-01/Accounts on
// the per-space host (`<space>.signalwire.com`) using HTTP Basic auth
// (project as username, token as password). Unverified-by-default — the
// space host isn't in the chunk; verify only fires when an apiBase override
// is supplied. Raw carries the project_id, RawV2 the token.
package signalwire

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

// SignalWire credentials are a two-part pair: Project ID + API token.
// Documented shapes (upstream trufflehog pkg/detectors/signalwire):
//   - Project ID: a UUID — [0-9a-z]{8}-{4}-{4}-{4}-{12}
//   - API token : exactly 50 alphanumeric chars — [0-9A-Za-z]{50}
//
// We keep a single token regex covering the high-variety credential shape so
// the id and token can both be harvested from the chunk, then disambiguate
// with the keyword arm regex + an entropy floor. The token half, carried in
// RawV2, is the value the entropy gate protects.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,128})\b`)

// minEntropy rejects low-information runs that clear the alphanumeric regex
// but are not real key material. The token charset is high-variety base62,
// so the 3.5 bits/char floor from the FP-hardening rubric applies without
// over-culling genuine 50-char base62 tokens.
const minEntropy = 3.5

// armRe is the assignment-anchored keyword gate. The bare "signalwire"
// substring over radius 256 matched any prose mention of the provider; this
// requires the keyword to sit next to a credential assignment within a tight
// window. The bare keyword stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)signalwire[_-]?(project|api[_-]?)?(token|key|secret|id|project)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SignalWire }

func (Scanner) Keywords() []string { return []string{"signalwire"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if _, dup := seen[v]; dup {
			continue
		}
		// Entropy floor: a high-variety base62 token clears 3.5 bits/char;
		// padded/dictionary/low-information runs that satisfy the bare
		// alphanumeric regex are dropped here.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	id, token := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.SignalWire,
		Raw:          []byte(id),
		RawV2:        []byte(token),
		Redacted:     redact(id),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, id+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
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
	window := lower[from:to]
	return armRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/laml/2010-04-01/Accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, tok)
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
