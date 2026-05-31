// Package leptonai detects Lepton AI workspace / user tokens — long alnum
// strings near a `lepton` reference. Verified via /api/v1/workspace on
// dashboard.lepton.ai with Bearer auth (Authorization: Bearer <TOKEN>).
//
// No authoritative source pins the token's length or charset. The official
// docs only describe usage (Bearer auth) and a combined credential structure
// `xxxxxx:************` (workspace-id ":" secret); they explicitly do not
// document a fixed length or charset for the secret body, the leptonai Python
// SDK treats it as an opaque `auth_token` string with no format validation,
// and upstream trufflehog ships no leptonai detector. Because the shape is an
// undocumented bare alnum run, a bare "lepton" substring over a wide window is
// far too loose a gate. We therefore apply recall-safe gate-tightening only:
// require a `lepton[_-]?(api[_-]?)?(token|key|secret)`-style reference within
// a tight 64-byte window, and gate on a conservative Shannon-entropy floor.
// We do NOT pin a length — no source documents one, and an invented length
// would silently destroy recall.
package leptonai

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://dashboard.lepton.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No prefix and no documented length, so the regex stays a bare alnum run
// (>=32) and the keyword gate + entropy floor carry the false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,})\b`)

// armRe is the assignment-style Lepton reference that must appear within the
// proximity window. A bare "lepton" substring (package names, comments, the
// dashboard URL) is too weak; "lepton_api_token" / "lepton-token" /
// "leptonkey" / "lepton_secret" is the shape a real token assignment or
// config key takes. The bare keyword stays in Keywords() as the prefilter.
var armRe = regexp.MustCompile(`(?i)lepton[_-]?(api[_-]?)?(token|key|secret)`)

// minEntropy is a conservative floor. No source documents the charset, so we
// avoid an aggressive (3.5) cut that would over-cull hex-shaped tokens
// (hex caps ~3.6); 3.0 rejects only low-information runs while preserving
// recall on real, undocumented-charset tokens.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LeptonAI }

func (Scanner) Keywords() []string { return []string{"lepton"} }

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
		// A `lepton[_-]?(api[_-]?)?(token|key|secret)` reference within a tight
		// window is mandatory — bare alnum runs are common (hashes, ids, nonces).
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: low-information runs that clear the alnum regex but lack
		// key-grade randomness are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.LeptonAI,
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

// nearKeyword reports whether a `lepton[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby LEPTON_API_TOKEN reference still arms.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/workspace", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
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
