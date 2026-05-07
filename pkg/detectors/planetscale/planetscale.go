// Package planetscale detects PlanetScale service token id + secret pairs
// (`pscale_oauth_…` / `pscale_tkn_…` + 32-64 char secret) and verifies
// them against /v1/organizations.
//
// PlanetScale service tokens grant database admin access (schema changes,
// branch deploys, query log access). Verified or shape-confirmed hits
// surface at SeverityCritical to make them stand out for prompt rotation.
package planetscale

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.planetscale.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Token id shapes (observed): `pscale_oauth_…`, `pscale_tkn_…` —
// followed by 32+ base62 characters.
var idRe = regexp.MustCompile(`\b(pscale_(?:oauth|tkn)_[A-Za-z0-9]{32,64})\b`)

// Secret is 32-64 base62 chars. Same noise as Algolia/Trello secrets;
// gated by `pscale_` co-occurrence + nearest-neighbor pairing.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// contextKeywords intentionally excludes the bare `pscale_` substring —
// every match already starts with `pscale_oauth_` / `pscale_tkn_`, so
// `pscale` is *always* in the surrounding window. We require a stronger
// signal (`planetscale` literal) to gate the result.
var contextKeywords = []string{"planetscale", "planetscale_token", "pscale_token"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PlanetScale }

func (Scanner) Keywords() []string { return []string{"pscale_", "planetscale"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ids := idRe.FindAllSubmatchIndex(data, -1)
	if len(ids) == 0 {
		return nil, nil
	}
	secrets := secretRe.FindAllSubmatchIndex(data, -1)
	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, m := range ids {
		id := string(data[m[2]:m[3]])
		if _, dup := seen[id]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[id] = struct{}{}
		secret, ok := nearestSecret(m[2], m[3], data, secrets, id)
		res := detectors.Result{
			DetectorType: detectors.PlanetScale,
			Raw:          []byte(id),
			Redacted:     redact(id),
			Severity:     detectors.SeverityCritical,
		}
		if ok {
			res.RawV2 = []byte(secret)
			res.ExtraData = map[string]string{"token_id": id}
			if verify {
				v, err := verifyPair(ctx, id, secret)
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	id, sec, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, id, sec)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, id, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/organizations", nil)
	if err != nil {
		return false, err
	}
	// PlanetScale uses Authorization: <token-id>:<secret>.
	req.Header.Set("Authorization", id+":"+secret)
	req.Header.Set("Accept", "application/json")

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

func nearestSecret(idStart, idEnd int, data []byte, hits [][]int, exclude string) (string, bool) {
	const maxDistance = 1024
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		// Skip hits that overlap the id span — id matches the secret regex.
		if h[2] < idEnd && h[3] > idStart {
			continue
		}
		s := string(data[h[2]:h[3]])
		if strings.HasPrefix(s, "pscale_") {
			continue
		}
		if s == exclude {
			continue
		}
		dist := abs(h[2] - idStart)
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

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func redact(t string) string {
	if len(t) <= 14 {
		return t
	}
	return t[:14] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
