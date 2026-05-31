// Package nearrpc detects NEAR Protocol RPC API keys (Pagoda, FastNEAR,
// Lava) — long alnum keys near a near-rpc-flavoured keyword. Unverified
// by design — RPC providers route per-endpoint and authentication
// schemes diverge per provider; verification fires only when an apiBase
// override is supplied.
package nearrpc

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// 32-64 alnum keys. No provider (FastNEAR, Pagoda) documents an
// authoritative length/charset/prefix for its RPC API key, so the length
// range is left untouched — pinning a guessed length would silently destroy
// recall. The false-positive load is carried instead by an assignment-anchor
// keyword gate (armRe within a tight window) plus a conservative entropy
// floor. See research record: no authoritative format found.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style NEAR-RPC reference that must appear within the
// proximity window. A bare "pagoda"/"fastnear"/"near-rpc" substring (docs
// links, dependency names, prose) is too weak; the shape a real credential
// assignment or config key takes is e.g. NEAR_RPC_API_KEY, PAGODA_API_KEY,
// fastnear-token, nearrpc_secret.
var armRe = regexp.MustCompile(`(?i)(near[_\-]?rpc|nearrpc|pagoda|fastnear|near[_\-]?protocol|nearprotocol)[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 32-64-char alnum runs that clear the regex
// and the keyword gate but are not random tokens (padded identifiers, repeated
// characters). Conservative 3.0 floor — the alnum charset can reach ~5.95
// bits/char, so 3.0 culls only obviously-structured runs without risking
// recall on a key whose true length/charset is undocumented.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.NearRPC }

func (Scanner) Keywords() []string { return []string{"near-rpc", "nearrpc", "pagoda", "fastnear"} }

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
		// Entropy gate: structured/low-information 32-64-char runs (padded
		// identifiers, repeated characters) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.NearRPC,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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

// nearKeyword reports whether an assignment-style NEAR-RPC reference (armRe)
// appears within a tight window on either side of the candidate token. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby PAGODA_API_KEY / NEAR_RPC_TOKEN reference still
// arms. Radius tightened 256->64 to cut cross-line false positives.
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
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := []byte(`{"jsonrpc":"2.0","id":"v","method":"status","params":[]}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", secret)
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
