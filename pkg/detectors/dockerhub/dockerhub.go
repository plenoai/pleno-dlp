// Package dockerhub detects Docker Hub personal access tokens. PATs are
// prefixed `dckr_pat_` and run ~36 url-safe characters.
//
// Verification is performed against Docker Hub's authenticated token
// endpoint: POST https://hub.docker.com/v2/auth/token with a JSON body
// {"identifier":<username>,"secret":<token>}. A 200 (a JWT is returned)
// means the credential is valid; 401 means it is invalid (or blocked by
// 2FA). This is the trufflehog dockerhub/v2 convention.
//
// NOTE: an earlier design used GET /v2/users/<username>/ on hub.docker.com
// for verification — that is WRONG. That endpoint is an UNAUTHENTICATED
// public profile lookup that returns 200 for any existing username
// regardless of token validity, so it never actually checks the token and
// would report false Verified=true.
//
// Verify requires BOTH a username and the token. The token alone is not
// sufficient, so when a username candidate is present in the same chunk we
// capture it (RawV2 + ExtraData["username"]) and verify the pair. When no
// username is present the Verify path no-ops (returns false, nil) and the
// finding surfaces unverified.
package dockerhub

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://hub.docker.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Token shape per the Docker Hub PAT issuance docs.
var tokenRe = regexp.MustCompile(`\b(dckr_pat_[A-Za-z0-9_-]{20,40})\b`)

// Capture a likely username if present near a `docker_username` /
// `DOCKER_USER` style key.
var usernameRe = regexp.MustCompile(`(?i)(?:docker[_-]?(?:hub[_-]?)?(?:user(?:name)?|login))\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_.-]{1,38})`)

// pairSep joins username and token into the single secret string that the
// engine-level Verify path receives. NUL can never appear in a Docker Hub
// username or token, so it is an unambiguous separator (datadog uses ':',
// but Docker usernames are url-safe and tokens are base64-ish — ':' is a
// safe separator there but NUL is unambiguous here regardless of charset).
const pairSep = "\x00"

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DockerHub }

func (Scanner) Keywords() []string { return []string{"dckr_pat_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	username := ""
	if um := usernameRe.FindSubmatch(data); len(um) == 2 {
		username = strings.ToLower(string(um[1]))
	}
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.DockerHub,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if username != "" {
			res.RawV2 = []byte(username)
			extra["username"] = username
			// Verification requires the username+token pair; only attempt it
			// when we actually have a username candidate.
			if verify {
				v, err := s.Verify(ctx, username+pairSep+token)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		// Token-only candidates (no username in chunk) are emitted unverified
		// so reviewers still see the surface area.
		out = append(out, res)
	}
	return out, nil
}

// Verify checks a Docker Hub username+token pair against the authenticated
// token endpoint. secret is expected as "<username>\x00<token>". When the
// username is missing the verify no-ops (false, nil).
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	username, token, ok := splitPair(secret)
	if !ok || username == "" || token == "" {
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	payload, err := json.Marshal(map[string]string{
		"identifier": username,
		"secret":     token,
	})
	if err != nil {
		return false, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v2/auth/token", bytes.NewReader(payload))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, transportErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, transportErr, []int{http.StatusOK}, []int{http.StatusUnauthorized})
}

func splitPair(s string) (username, token string, ok bool) {
	i := strings.Index(s, pairSep)
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+len(pairSep):], true
}

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
