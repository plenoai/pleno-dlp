// Package jenkinsx detects Jenkins X (jx) API tokens — long alnum tokens
// near a `jenkinsx`/`jx_token`-style reference. Self-hosted: per-installation
// host is not in the chunk, so this detector is unverified-by-design (apiBase
// override available for tests / explicit configuration).
//
// FORMAT RESEARCH (inconclusive): Jenkins X does not mint a native API
// credential with a documented prefix/length/charset. `jx boot` consumes the
// underlying SCM access token (GitHub/GitLab/Bitbucket) and merely validates a
// >=40-char minimum length (jenkins-x/jx#7358); the original GitHub-classic
// `^[0-9a-f]{40}$` shape it assumed was later broken by GitHub's own format
// change (jenkins-x/jx#7633). There is no authoritative Jenkins X token format
// to anchor a prefix or pin an exact length against, and trufflehog ships no
// jenkins/jenkinsx detector to mirror. We therefore keep the broad `{40,80}`
// alnum body (recall-safe) and carry the false-positive load on a tight,
// assignment-anchored keyword gate plus a conservative entropy floor.
package jenkinsx

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "" // self-hosted; empty = unverified.

var httpClient = &http.Client{Timeout: 10 * time.Second}

// No authoritative Jenkins X token format exists (see package doc), so we do
// not pin an exact length or anchor a prefix — that would silently destroy
// recall. The body stays a broad 40-80 char alnum run; the keyword gate and
// entropy floor below reject the noise this otherwise admits.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{40,80})\b`)

// armRe is the assignment-style Jenkins X reference that must appear within the
// proximity window. A bare "jenkinsx"/"jx" substring (script URLs, package
// names, comments) is too weak; a `jenkinsx_token` / `jx-api-key` shape is what
// a real token assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)(jenkins[_\-]?x|jx)[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy rejects low-entropy 40-80 char runs that clear the alnum regex but
// are not random tokens (repeated/structured identifiers, padded names). Hex
// caps ~3.6 bits/char and we cannot rule out a hex-shaped SCM token, so 3.0 is
// the conservative floor — high enough to drop obvious non-secrets, low enough
// to keep any real token.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.JenkinsX }

func (Scanner) Keywords() []string { return []string{"jenkinsx", "jenkins_x", "jx_"} }

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
		// Entropy gate: structured/low-information 40-80 char runs (repeated
		// substrings, padded identifiers) are rejected even if armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.JenkinsX,
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

// nearKeyword reports whether a `jenkinsx_token`-style reference (armRe)
// appears within a tight window on either side of the token. The window spans
// both directions (not strict immediate precedence) so a token defined
// alongside a nearby reference still arms.
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

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/me", nil)
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
