// Package bitbucketcloud detects Bitbucket Cloud (Atlassian) access tokens and
// app passwords, verifying them as Bearer credentials against /2.0/user.
//
// Two authoritative shapes, both carrying a distinguishing Atlassian prefix:
//
//  1. ATCTT3xFfG… — repo/workspace/project access token (Atlassian "API token"
//     family). Upstream trufflehog anchors on the literal `ATCTT3xFfG` prefix
//     followed by a base64url-ish body that ends with `=` plus an 8-char
//     alphanumeric checksum.
//     Ref: trufflesecurity/trufflehog pkg/detectors/atlassian/v2/atlassian.go
//     `\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`.
//
//  2. ATBB… — Bitbucket Cloud app password / API token. Upstream anchors on the
//     literal `ATBB` prefix; charset `[A-Za-z0-9_=.-]`, no documented fixed
//     length.
//     Ref: trufflesecurity/trufflehog pkg/detectors/bitbucketapppassword/
//     bitbucketapppassword.go (password group `ATBB[A-Za-z0-9_=.-]+`).
//
// Both prefixes are distinctive enough to identify the credential without a
// keyword window or entropy floor, so neither is applied here. The previous
// bare `[A-Za-z0-9]{32}` "legacy" pattern had no authoritative basis (no source
// documents a 32-char prefixless Bitbucket credential) and was a false-positive
// generator; it is removed in favour of the documented `ATBB` shape.
package bitbucketcloud

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.bitbucket.org"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Modern Atlassian API token. Mirror of trufflehog atlassian/v2.
	tokenRe = regexp.MustCompile(`\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`)
	// Bitbucket Cloud app password / API token. Mirror of trufflehog
	// bitbucketapppassword (password capture group).
	appPasswordRe = regexp.MustCompile(`\b(ATBB[A-Za-z0-9_=.-]+)\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.BitbucketCloud }

func (Scanner) Keywords() []string { return []string{"bitbucket", "ATCTT3xFfG", "ATBB"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	for _, re := range []*regexp.Regexp{tokenRe, appPasswordRe} {
		for _, m := range re.FindAllSubmatch(data, -1) {
			token := string(m[1])
			if _, dup := seen[token]; dup {
				continue
			}
			seen[token] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.BitbucketCloud,
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
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/2.0/user", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

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
