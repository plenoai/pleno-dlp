// Package fivetran detects Fivetran API key + secret pairs near the
// `fivetran` keyword. Verified via /v1/users on api.fivetran.com using
// HTTP Basic auth (key as username, secret as password).
package fivetran

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.fivetran.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Fivetran API keys/secrets are 20 alnum each. We pair them by proximity.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{20})\b`)

// anchorRe is an assignment-style Fivetran reference (env/config/source shape)
// that must sit within anchorRadius bytes of one half of a candidate pair.
// Without it, the bare keyword "fivetran" anywhere in a 256B window paired any
// two adjacent 20-char alnum runs — README hashes, git SHAs, build IDs, etc.
var anchorRe = regexp.MustCompile(`(?i)fivetran[_\- ]?(?:api[_\- ]?key|key|secret|token)\s*[:=]`)

// minEntropy is a SECONDARY gate. Fivetran 20-char alnum IDs measure ~3.9
// bits/char, so the floor is deliberately 3.0 (not 3.5) to reject only runs
// of repeated/structured characters, never a real ID. The assignment anchor
// above is the primary precision lever.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Fivetran }

func (Scanner) Keywords() []string { return []string{"fivetran"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	// Anchor positions: assignment-style fivetran references in the chunk.
	anchors := anchorRe.FindAllIndex(data, -1)
	if len(anchors) == 0 {
		return nil, nil
	}
	// Pair adjacent matches where one half sits near an assignment anchor.
	var paired [][2]string
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(hits); i++ {
		a := string(data[hits[i][2]:hits[i][3]])
		b := string(data[hits[i+1][2]:hits[i+1][3]])
		if a == b {
			continue
		}
		// Anchor must be near one half of the pair (radius 64, not 256).
		if !nearAnchor(anchors, hits[i][2], hits[i][3]) && !nearAnchor(anchors, hits[i+1][2], hits[i+1][3]) {
			continue
		}
		// Secondary entropy gate: reject repeated/structured 20-char runs.
		if !detectors.HasMinEntropy(a, minEntropy) || !detectors.HasMinEntropy(b, minEntropy) {
			continue
		}
		k := a + ":" + b
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		paired = append(paired, [2]string{a, b})
	}
	if len(paired) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(paired))
	for _, p := range paired {
		key, secret := p[0], p[1]
		res := detectors.Result{
			DetectorType: detectors.Fivetran,
			Raw:          []byte(key),
			RawV2:        []byte(key + ":" + secret),
			Redacted:     redact(key),
		}
		if verify {
			v, err := s.Verify(ctx, key+":"+secret)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

// nearAnchor reports whether any assignment anchor lies within anchorRadius
// bytes of the [start,end) token span.
func nearAnchor(anchors [][]int, start, end int) bool {
	const anchorRadius = 64
	for _, a := range anchors {
		// a = [anchorStart, anchorEnd). Treat the anchor as adjacent if its
		// span comes within anchorRadius of the token span on either side.
		if a[0] <= end+anchorRadius && a[1] >= start-anchorRadius {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, pair string) (bool, error) {
	parts := strings.SplitN(pair, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/users", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(parts[0], parts[1])
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
