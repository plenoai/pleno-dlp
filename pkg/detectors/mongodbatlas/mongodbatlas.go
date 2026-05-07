// Package mongodbatlas detects MongoDB Atlas Programmatic API key pairs
// (8-char public key + UUID-shaped private key) and verifies them against
// /api/atlas/v2/orgs.
//
// Limitation: Atlas's preferred auth scheme is HTTP Digest, not Basic. We use
// Basic for the MVP because Go's stdlib doesn't ship a Digest client and
// hand-rolling one is out of scope for an initial detector landing. The
// upstream API still returns 401 / 200 cleanly with Basic during the
// challenge phase, which is enough to distinguish "valid pair" from "invalid
// pair". When upstream behavior tightens we'll revisit and bring a Digest
// client (likely github.com/icholy/digest) in via an architect ADR.
//
// Naming awkwardness: Atlas calls these "public" and "private" keys, but the
// public key has the size and shape of a username and the private key is the
// password. We keep the Atlas vocabulary so docs match the provider.
package mongodbatlas

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://cloud.mongodb.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Public key: 8 lowercase letters (e.g. "abcdefgh"). Private key: UUID
// shape (8-4-4-4-12 hex). The 8-letter shape is generic, so we require a
// co-occurring "mongodb" / "atlas" / "MONGODB_ATLAS_" keyword in the
// surrounding 256-byte window.
var (
	pubRe  = regexp.MustCompile(`\b([a-z]{8})\b`)
	privRe = regexp.MustCompile(`\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`)
)

var contextKeywords = []string{"mongodb", "atlas", "mongodb_atlas"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MongoDBAtlas }

func (Scanner) Keywords() []string { return []string{"mongodb", "atlas"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	privs := privRe.FindAllSubmatchIndex(data, -1)
	if len(privs) == 0 {
		return nil, nil
	}
	pubs := pubRe.FindAllSubmatchIndex(data, -1)

	lower := strings.ToLower(string(data))

	out := make([]detectors.Result, 0, len(privs))
	seen := map[string]struct{}{}
	for _, m := range privs {
		priv := string(data[m[2]:m[3]])
		if _, dup := seen[priv]; dup {
			continue
		}
		// Co-occurrence with a context keyword is mandatory — UUIDs alone are
		// way too common to surface as Atlas keys.
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[priv] = struct{}{}
		pub, ok := nearestPub(m[2], data, pubs)
		res := detectors.Result{
			DetectorType: detectors.MongoDBAtlas,
			Raw:          []byte(priv),
			Redacted:     redact(priv),
		}
		if ok {
			// The Atlas vocabulary is "public" + "private"; the API uses the
			// public key as the Basic-auth username. Surface the pub via
			// ExtraData so reviewers see the pairing without ambiguity.
			res.RawV2 = []byte(pub)
			res.ExtraData = map[string]string{"public_key": pub}
			if verify {
				v, err := verifyPair(ctx, pub, priv)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		// Single-key (no public key partner) candidates emit unverified — the
		// detector still flags the leaked private key so the operator can
		// rotate, but Verify isn't possible without the username half.
		out = append(out, res)
	}
	return out, nil
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

func nearestPub(privStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		dist := abs(start - privStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
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
	pub, priv, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, pub, priv)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, pub, priv string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/atlas/v2/orgs", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(pub, priv)
	req.Header.Set("Accept", "application/vnd.atlas.2024-08-05+json")

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

func redact(priv string) string {
	if len(priv) <= 8 {
		return priv
	}
	return priv[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
