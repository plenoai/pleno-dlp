// Package mercurybank detects Mercury Bank API tokens. Mercury (mercury.com)
// issues read-write banking tokens — a leaked token grants ACH/wire visibility,
// so verified hits surface SeverityCritical via DefaultSeverity. Verified via
// /api/v1/accounts with Bearer auth on api.mercury.com.
//
// Mercury tokens carry a strong, self-describing prefix documented at
// https://docs.mercury.com/reference/getting-started-with-your-api — every
// token has the literal shape:
//
//	secret-token:mercury_<env>_<type>_<body>_yrucrem
//
// where <env> is production|sandbox, <type> is a short classifier (e.g. wma),
// <body> is a long base62 run (underscore-segmented), and the token ends with
// the literal "_yrucrem" suffix ("mercury" reversed). Because the prefix is
// highly distinctive we anchor the regex on it — no entropy floor or keyword
// proximity gate is needed (anchoring is the gate). This replaces the prior
// bare [A-Za-z0-9]{32,120} + radius-256 substring gate, which matched any long
// alphanumeric near the word "mercury" (commit SHAs, nonces, unrelated tokens).
//
// Doc-comment example uses <BODY> as a placeholder to avoid leak-scanner flags.
// Real shape: secret-token:mercury_production_wma_<BODY>_yrucrem
package mercurybank

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.mercury.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe anchors on the documented Mercury prefix. The capture spans the whole
// credential (including the "secret-token:" prefix) because that full string is
// what Mercury accepts as the Bearer credential. The body is base62 plus the
// underscore segment separators Mercury uses; the token closes on the literal
// "_yrucrem" suffix. Anchoring on this prefix is the false-positive gate, so no
// entropy floor or keyword-proximity window is required.
var tokenRe = regexp.MustCompile(`secret-token:mercury_(?:production|sandbox)_[A-Za-z0-9]+_[A-Za-z0-9_]+_yrucrem`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.MercuryBank }

// Keywords retains "mercury" as the cheap engine-level prefilter; the anchored
// regex carries the actual disambiguation.
func (Scanner) Keywords() []string { return []string{"mercury"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.MercuryBank,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/accounts", nil)
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
	// Keep the descriptive prefix visible (it is not itself secret), mask the
	// random body. The documented prefix runs through "..._wma_"; redact after
	// the env+type segments so triage can see which environment leaked.
	const keep = len("secret-token:mercury_production_")
	if len(t) <= keep {
		if len(t) <= 8 {
			return t
		}
		return t[:8] + "..."
	}
	return t[:keep] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
