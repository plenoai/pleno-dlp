// Package sift detects Sift Science API key + account id pairs near
// the `sift` keyword. Paired credential per the trufflehog convention
// — Raw=accountId, RawV2=accountId+":"+apiKey. Verified via HTTP Basic
// auth on api.sift.com /v205/users/_test_user.
//
// "sift" is a short English word substring (sifted, sifting, sifter,
// shift...). The previous detector did `strings.Contains(window,
// "sift")` over a 256-byte window AND used a `[A-Za-z0-9]{20,80}`
// token regex — together they fired on essentially any block of text
// containing a 20+ char identifier within 256 bytes of any of those
// words. The new detector requires an explicit Sift anchor
// (`sift_api`, `sift_account`, `siftscience`, `sift.com`, `SIFT=`).
package sift

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.sift.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Sift Science accountId/apiKey are documented as 20-80 char
// alphanumeric strings. We rely on the keywordRe gate to suppress
// generic blob FPs.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20,80})\b`)

// keywordRe requires an explicit Sift anchor. The bare substring
// "sift" no longer satisfies, so prose like `sifted`, `sifting`,
// `shift`, `sifter` is rejected.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`sift[_\-]api(?:[_\-]key|[_\-]token)?` +
	`|sift[_\-]account[_\-]id` +
	`|sift[_\-]account` +
	`|sift[_\-]key` +
	`|sift[_\-]token` +
	`|\bsiftscience\b` +
	`|\bsift\.com\b` +
	`|\bapi\.sift\.com\b` +
	`|\bsift[ \t]*[:=][ \t]*` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Sift }

func (Scanner) Keywords() []string { return []string{"sift"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	var ident, token string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		if ident == "" {
			ident = v
			continue
		}
		if v == ident {
			continue
		}
		token = v
		break
	}
	if ident == "" || token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Sift,
		Raw:          []byte(ident),
		RawV2:        []byte(ident + ":" + token),
		Redacted:     redact(ident),
	}
	if verify {
		v, err := s.Verify(ctx, ident+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 128
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	ident, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v205/accounts/"+ident, nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(tok + ":"))
	req.Header.Set("Authorization", "Basic "+auth)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
