// Package dockerhub detects Docker Hub personal access tokens. PATs are
// prefixed `dckr_pat_` and run ~36 url-safe characters.
//
// Verify is intentionally not performed inline. Docker Hub's
// /v2/users/login endpoint requires {username, password|token} — the
// token alone isn't enough; the username is rarely embedded next to the
// token in source. So dockerhub surfaces unverified-by-design at
// SeverityHigh and the engine renders it under --unverified-results.
// When a username candidate is present in the same chunk we attach it as
// RawV2 so reviewers can rotate the right account.
package dockerhub

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Token shape per the Docker Hub PAT issuance docs.
var tokenRe = regexp.MustCompile(`\b(dckr_pat_[A-Za-z0-9_-]{20,40})\b`)

// Capture a likely username if present near a `docker_username` /
// `DOCKER_USER` style key.
var usernameRe = regexp.MustCompile(`(?i)(?:docker[_-]?(?:hub[_-]?)?(?:user(?:name)?|login))\s*[:=]\s*["']?([A-Za-z0-9][A-Za-z0-9_.-]{1,38})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.DockerHub }

func (Scanner) Keywords() []string { return []string{"dckr_pat_"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		}
		out = append(out, res)
	}
	return out, nil
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
