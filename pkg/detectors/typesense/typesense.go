// Package typesense detects Typesense API keys. Generated keys are
// fixed 32-character alphanumeric strings with no prefix — the official
// Cloud Management API docs show admin/search keys like
// <UUID-LIKE-32-CHAR-TOKEN>. A bare 32-char alnum run is a generic shape
// (commit SHAs, base62 ids, nonces hit constantly), so we (1) pin the
// documented length exactly, (2) require a `typesense[_-]?(api[_-]?)?
// (key|token|secret)` reference within a tight 64-byte window, and (3)
// gate on Shannon entropy before surfacing. Unverified by design —
// Typesense is self-hosted or per-cluster
// (`<cluster>.a1.typesense.net`); verification fires only when an
// apiBase override is supplied.
//
// Source for the 32-char alnum format: Typesense Cloud Management API
// docs (https://typesense.org/docs/cloud-management-api/v1/cluster-management.html),
// which return generated keys such as the 32-char admin_key /
// search_only_key examples.
package typesense

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

// Typesense keys are documented as exactly 32 alphanumeric characters
// with no distinguishing prefix, so the length is pinned and the keyword
// gate plus entropy floor carry the false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// armRe is the assignment-style Typesense reference that must appear
// within the proximity window. A bare "typesense" substring (docs links,
// package names, host names like `<cluster>.typesense.net`) is too weak;
// `typesense_api_key` / `typesense-key` / `typesensesecret` is the shape a
// real key assignment or config entry takes.
var armRe = regexp.MustCompile(`(?i)typesense[_\-]?(api[_\-]?)?(key|token|secret)`)

// minEntropy rejects low-entropy 32-char runs that clear the alnum regex
// but are not random keys (e.g. structured identifiers, padded names).
// 3.5 is the documented threshold for no-prefix fixed-length high-variety
// alnum credentials; the real 32-char Typesense examples sit at ~4.6.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Typesense }

func (Scanner) Keywords() []string { return []string{"typesense"} }

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
		// Entropy gate: structured/low-information 32-char runs (e.g. a
		// dotted identifier or padded name) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Typesense,
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

// nearKeyword reports whether a `typesense[_-]?(api[_-]?)?(key|token|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a key
// defined alongside a nearby TYPESENSE_API_KEY reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/health", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-TYPESENSE-API-KEY", secret)
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
