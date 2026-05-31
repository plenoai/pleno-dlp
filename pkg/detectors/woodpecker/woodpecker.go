// Package woodpecker detects Woodpecker CI access tokens near the
// `woodpecker` keyword. Woodpecker CI is self-hosted; the verify endpoint
// lives on the per-installation host which isn't carried in the chunk, so
// this is unverified-by-default with apiBase override for tests.
//
// Token format (authoritative): Woodpecker CI personal-access / session
// tokens are HS256 JWTs minted by the server via golang-jwt. They have the
// canonical JWT shape `<header>.<payload>.<signature>` — three base64url
// segments separated by dots, with the header always starting `eyJ`
// (base64url of `{"`). See shared/token/token.go in woodpecker-ci/woodpecker:
//
//	const SignerAlgo = "HS256"
//	token := jwt.New(jwt.SigningMethodHS256)
//	return token.SignedString([]byte(secret))
//
// The previous regex (`[A-Za-z0-9]{32,64}`) was wrong for this format — it
// matched bare alphanumeric runs (and could never match a real dotted JWT as
// a whole), producing pure false-positive noise. Anchoring on the JWT
// structure is the distinguishing "prefix" per the hardening rubric, so no
// entropy floor is needed: a base64url string with two dots and an `eyJ`
// header is already a near-unique shape.
package woodpecker

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

// tokenRe matches the canonical JWT shape used by Woodpecker CI: an `eyJ`
// header, a base64url payload, and a base64url signature, dot-separated.
// Mirrors the repo's jwt detector regex.
var tokenRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

// contextRe is the windowed keyword gate. It replaces the bare
// strings.Contains(window, "woodpecker") over radius 256 with an
// assignment-anchor arm regex over radius 64, so a `woodpecker` mention far
// from an unrelated JWT no longer arms the detector. The bare keyword stays
// in Keywords() as the engine prefilter.
var contextRe = regexp.MustCompile(`(?i)woodpecker[_-]?(ci[_-]?)?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Woodpecker }

func (Scanner) Keywords() []string { return []string{"woodpecker"} }

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
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Woodpecker,
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
	return contextRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/user", nil)
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
