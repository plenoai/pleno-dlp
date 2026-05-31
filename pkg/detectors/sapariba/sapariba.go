// Package sapariba detects SAP Ariba Application Keys (the apiKey header
// value) near the `ariba` keyword. Unverified by design — Ariba routes per
// region (`<region>.api.ariba.com`) and per-realm; verification fires
// only when an apiBase override is supplied.
//
// Format (authoritative): the Application Key is a fixed 32-char,
// mixed-case alphanumeric string with no public prefix. Confirmed by the
// official SAP samples, e.g. <APPLICATION-KEY> values shown as
// "uEnCwXMo7YYmQE7el7iqqciAqT7Og0Ik" and "Qmn0qCueIwEYXAoiqgY77lqEOk77iTMc"
// in SAP-samples/ariba-extensibility-samples
// (topics/apis/recipes/retrieve-sourcing-requests-from-api.ipynb).
package sapariba

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

// Application Key: exactly 32 mixed-case alphanumeric chars, no prefix
// (per SAP-samples). The bare shape collides with many random secrets, so
// the entropy floor and the assignment-anchored keyword gate disambiguate.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minEntropy rejects git-SHA-shaped / low-information 32-char runs that
// clear the regex but lack key-grade randomness. 3.5 bits/char is the
// high-variety (mixed-case alnum) floor; a real 32-char base62 key clears
// it comfortably while 32-char hex (caps ~4.0 but commonly structured) and
// repetitive runs are culled.
const minEntropy = 3.5

// contextRe is the windowed assignment-anchor gate. Replaces a bare
// strings.Contains(window, "ariba") which matched prose; this requires an
// assignment-style ariba api/token/key/secret form near the token.
var contextRe = regexp.MustCompile(`(?i)ariba[_-]?(api[_-]?)?(token|key|secret)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SAPAriba }

func (Scanner) Keywords() []string { return []string{"ariba"} }

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
			DetectorType: detectors.SAPAriba,
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
	window := lower[from:to]
	return contextRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/sourcing/v2/prod/users", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("apiKey", secret)
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
