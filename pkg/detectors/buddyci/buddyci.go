// Package buddyci detects Buddy CI/CD personal access tokens. Buddy's API
// documentation transmits the token as a Bearer credential whose canonical
// example is a UUID v4 — e.g. the Hello World page's literal curl call
//
//	curl --header "Authorization: Bearer <UUID-V4-TOKEN>" \
//	     https://api.buddy.works/user
//
// (see https://buddy.works/docs/api/getting-started/hello-world and
// https://buddy.works/docs/api/getting-started/oauth2/personal-access-token,
// which shows the same UUID shape). The token therefore has no prefix and is
// hyphenated lowercase hex, not a long base64url run. We anchor the regex on
// the UUID structure — itself highly distinguishing — and back it with a
// `buddy[_-]?(api[_-]?)?(token|key|secret)`-style assignment reference within a
// tight 64-byte window plus a conservative Shannon-entropy floor (real v4
// UUIDs sit ~3.6 bits/char; degenerate all-zero/repeated UUIDs sit ~0.5).
// Verified via /user on api.buddy.works using `Authorization: Bearer <token>`.
package buddyci

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.buddy.works"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Buddy tokens are UUID v4 — 8-4-4-4-12 hyphenated lowercase hex, no prefix.
// Source: buddy.works API docs (Hello World / Personal Access Token pages)
// show literal example tokens like 732e9e20-50ba-4047-8a7b-c9b17259a2a2. The
// UUID structure is itself the anchor; we accept upper- or lower-case hex.
var tokenRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

// armRe is the assignment-style Buddy reference that must appear within the
// proximity window. A bare "buddy" substring (dependency names, comments,
// URLs) is too weak; "buddy_token" / "buddy-api-key" / "buddysecret" is the
// shape a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)buddy[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects degenerate UUIDs (all-zero, repeated nibbles) that clear
// the structural regex but carry no secret material. Real v4 UUIDs sit
// ~3.6 bits/char; the documented hex alphabet caps near 4.0, so 3.0 is the
// recall-safe floor for this low-variety charset (3.5 would over-cull).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BuddyCI }

func (Scanner) Keywords() []string { return []string{"buddy"} }

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
		// Entropy gate: reject degenerate UUIDs (all-zero, repeated nibbles)
		// that satisfy the structural regex but hold no secret material.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.BuddyCI,
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

// nearKeyword reports whether a `buddy[_-]?(api[_-]?)?(token|key|secret)`
// reference appears within a tight window on either side of the token. The
// window spans both directions (not strict immediate precedence) so a token
// defined alongside a nearby BUDDY_TOKEN reference still arms. Radius 64
// (down from 256) keeps the gate from arming on an unrelated `buddy` mention a
// paragraph away.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/user", nil)
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
