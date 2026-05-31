// Package fastspring detects FastSpring API credentials — a paired
// username + password near the `fastspring` keyword. Verified via /accounts
// on api.fastspring.com using HTTP Basic auth. Raw carries the username,
// RawV2 carries the password.
//
// FastSpring's docs (developer.fastspring.com, the Classic API authentication
// page, and the FastSpring/fastspring-api repo) state the API username and
// password are dashboard-generated and case-sensitive, but DO NOT document a
// fixed length, prefix, or character set, and there is no upstream trufflehog
// detector to mirror. With no authoritative format we keep the original
// `{16,32}` alphanumeric shape (NOT a documented length — do not over-tighten)
// and apply only recall-safe gate-tightening: an assignment-anchor arm regex
// within a 64-byte window (replacing the radius-256 bare substring) plus a
// conservative entropy floor.
package fastspring

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.fastspring.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// {16,32} alphanumeric: the original shape, retained because no authoritative
// FastSpring source documents the credential length or charset. A bare
// alphanumeric run of this shape is generic, so the arm regex and entropy floor
// carry the false-positive load.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{16,32})\b`)

// armRe is the assignment-style FastSpring reference that must appear within
// the proximity window. A bare "fastspring" substring (doc links, the
// api.fastspring.com host, dependency names) is too weak a gate against a
// generic 16-32 alphanumeric run;
// `fastspring[_-]?(api[_-]?)?(user|pass|token|key|secret|credential)` is the
// shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)fastspring[_\-]?(api[_\-]?)?(user(name)?|pass(word)?|token|key|secret|credential)`)

// minEntropy rejects low-information 16-32 char runs that clear the alnum regex
// but are not random credentials (e.g. padded placeholders, repeated chars).
// 3.0 is conservative: FastSpring does not document the charset/variety, so we
// avoid the 3.5 floor that could over-cull a real credential.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.FastSpring }

func (Scanner) Keywords() []string { return []string{"fastspring"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		user := string(data[h[2]:h[3]])
		if _, dup := seen[user]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate on the username half: padded placeholders and repeated
		// runs clear the alnum regex but are not real credentials.
		if !detectors.HasMinEntropy(user, minEntropy) {
			continue
		}
		var pass string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand == user || !nearKeyword(lower, h2[2], h2[3]) {
				continue
			}
			// Entropy gate on the password half as well — both halves of the
			// pair must look like random credentials.
			if !detectors.HasMinEntropy(cand, minEntropy) {
				continue
			}
			pass = cand
			break
		}
		if pass == "" {
			continue
		}
		seen[user] = struct{}{}
		seen[pass] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.FastSpring,
			Raw:          []byte(user),
			RawV2:        []byte(pass),
			Redacted:     redact(user),
		}
		if verify {
			v, err := s.Verify(ctx, user+":"+pass)
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

// nearKeyword reports whether a
// `fastspring[_-]?(api[_-]?)?(user|pass|token|key|secret|credential)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a
// credential defined alongside a nearby FASTSPRING_USERNAME / FASTSPRING_PASSWORD
// reference still arms.
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	user, pass := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
