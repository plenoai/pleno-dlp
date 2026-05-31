// Package bitbucketserver detects Bitbucket Server (Data Center, formerly
// Stash) HTTP access tokens and personal access tokens.
//
// Both shapes are Bitbucket Data Center bearer tokens sent as
// `Authorization: Bearer <token>` against the Bitbucket Server REST API, so the
// matched secret IS the API auth credential — a probe against the REST API is a
// correct verification. Bitbucket Server is self-hosted, so the host is neither
// fixed nor derivable from the token body (BBDC- bodies are opaque base64url and
// the PAT is plain hex). When no host is supplied via the package-level apiBase
// override, Verify no-ops (Verified=false, VerificationErr=nil) so we never
// covertly scan a guessed host; with apiBase set (operator-supplied), only
// 200/403 from the customer's own Bitbucket assert validity.
//
// Two distinct token shapes:
//   - HTTP access token: `BBDC-<base64url>` (~70 chars, project/repo scope).
//   - PAT minted by /plugins/servlet/access-tokens: 40 hex chars near the
//     `bitbucket` keyword.
package bitbucketserver

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the Bitbucket Server/Data Center REST root. It is empty by default:
// the host is self-hosted and rarely present in the chunk, so without an
// operator-supplied override Verify no-ops rather than probing a guessed host.
// Tests override this to point at an httptest server.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// GET /rest/api/1.0/users is admin-permission-gated, so a VALID non-admin token
// returns 403 — that is a live token with insufficient scope, NOT an invalid
// credential. Accept both 200 and 403 as valid; reject only 401 (no/invalid
// credentials). 429 and 5xx are surfaced as transient errors by
// ClassifyVerifyHTTP.
var (
	acceptCodes = []int{http.StatusOK, http.StatusForbidden}
	rejectCodes = []int{http.StatusUnauthorized}
)

var (
	// Bitbucket Data Center HTTP access tokens / PATs carry a `BBDC-` prefix
	// followed by a base64-style body. Charset and `{40,50}` length window
	// mirror the authoritative upstream trufflehog detector
	// (pkg/detectors/atlassiandatacenter/bitbucketdatacenter):
	// `\b(BBDC-[A-Za-z0-9+/@_-]{40,50})`. The `BBDC-` prefix is the
	// distinguishing anchor, so no entropy floor is needed on this shape.
	httpAccessRe = regexp.MustCompile(`\b(BBDC-[A-Za-z0-9+/@_-]{40,50})`)
	// Some self-hosted deployments expose a prefix-less 40-char base62 PAT.
	// No authoritative source pins this length/charset (Atlassian docs do
	// not document a prefix-less format; upstream trufflehog only matches
	// the BBDC- form), so this branch is conservatively gate-tightened: an
	// assignment-anchor arm regex within a tight window plus an entropy
	// floor. The bare 40-char shape is otherwise indistinguishable from
	// commit SHAs, nonces, and object names.
	patRe = regexp.MustCompile(`\b([A-Za-z0-9]{40})\b`)
)

// armRe is the assignment-style Bitbucket reference that must appear within the
// proximity window of a prefix-less PAT candidate. A bare "bitbucket"/"stash"
// substring (doc prose, dependency names, URLs) is too weak to gate a generic
// 40-char run; `bitbucket_token` / `stash-api-key` / `bb_pat secret` is the
// shape a real credential assignment or config key takes. The bare keywords
// remain in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)(?:bitbucket|stash|bbserver|bb)[\s_-]?(?:api[\s_-]?)?(?:token|key|secret|pat)`)

// minEntropy rejects low-entropy 40-char runs that clear the base62 regex but
// are not random credentials (e.g. structured identifiers, padded names). A
// 40-char base62 PAT is a high-variety charset, so the 3.5 floor applies per
// the format-hardening rubric.
const minEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BitbucketServer }

func (Scanner) Keywords() []string { return []string{"BBDC-", "bitbucket"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	add := func(token string) {
		res := detectors.Result{
			DetectorType: detectors.BitbucketServer,
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

	for _, m := range httpAccessRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		add(token)
	}

	lower := strings.ToLower(string(data))
	patHits := patRe.FindAllSubmatchIndex(data, -1)
	for _, h := range patHits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Skip if this token is the body of a BBDC- token already captured.
		if strings.Contains(token, "-") {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Entropy gate: structured/low-information 40-char runs (padded
		// identifiers, repeated chars) are rejected even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		// Bitbucket Cloud detector owns ATCTT3xFfGF0… tokens — skip those.
		if strings.HasPrefix(token, "ATCTT") {
			continue
		}
		seen[token] = struct{}{}
		add(token)
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify probes the Bitbucket Server REST API with the token as a bearer
// credential. The host comes solely from the operator-supplied apiBase override;
// when apiBase is empty the verification no-ops (Verified=false, err=nil) so we
// never scan a guessed self-hosted host.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/rest/api/1.0/users?limit=1", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, acceptCodes, rejectCodes)
}

// nearKeyword reports whether an assignment-style Bitbucket credential
// reference (armRe) appears within a tight window on either side of a
// prefix-less PAT candidate. The window spans both directions (not strict
// immediate precedence) so a token defined alongside a nearby reference still
// arms. Radius is 64 (was 256): a bare keyword 256 bytes away is too weak a
// signal for a generic 40-char run.
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

func redact(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
