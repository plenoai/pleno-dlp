// Package plivo detects Plivo Auth ID + Auth Token credentials — a paired
// detector. Auth IDs start with `MA` (master) or `SA` (subaccount) followed
// by 18 uppercase alphanumeric chars; tokens are >=40 base64url. Verified
// via /v1/Account/{auth_id}/ on api.plivo.com using HTTP Basic auth. Raw
// carries the auth_id, RawV2 carries the auth_token.
package plivo

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.plivo.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

// MA / SA + 18 uppercase alnum
var authIDRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`\b((?:MA|SA)[A-Z0-9]{18})\b`) })

// Auth tokens are 40+ base64url
var tokenRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`\b([A-Za-z0-9_-]{40,128})\b`) })

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Plivo }

func (Scanner) Keywords() []string { return []string{"MA", "SA", "plivo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := findAuthIDs(data)
	if len(idHits) == 0 {
		return nil, nil
	}
	tHits := tokenRe().FindAllSubmatch(data, -1)
	if len(tHits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, idm := range idHits {
		authID := string(idm)
		if _, dup := seen[authID]; dup {
			continue
		}
		var token string
		for _, tm := range tHits {
			cand := string(tm[1])
			if cand == authID {
				continue
			}
			// Plivo auth_ids are 20 chars; tokens are >= 40. Skip anything
			// shorter than 40 to avoid pairing two auth_ids together.
			if len(cand) < 40 {
				continue
			}
			token = cand
			break
		}
		if token == "" {
			continue
		}
		seen[authID] = struct{}{}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Plivo,
			Raw:          []byte(authID),
			RawV2:        []byte(token),
			Redacted:     redact(authID),
		}
		if verify {
			v, err := s.Verify(ctx, authID+":"+token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return detectors.SafeResults(out), nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	authID, token := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v1/Account/"+authID+"/", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(authID, token)
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

// findAuthIDs returns exactly the group-1 matches of authIDRe
// (\b((?:MA|SA)[A-Z0-9]{18})\b, leftmost non-overlapping). The keywords
// "MA"/"SA" hit almost every chunk case-insensitively, and the regexp has
// no literal prefix, so the NFA pass over every window was the costliest
// detector in full-history scans; a fixed-width byte scan is equivalent.
func findAuthIDs(data []byte) [][]byte {
	const width = 20
	var out [][]byte
	for i := 0; i+width <= len(data); {
		j := bytes.IndexAny(data[i:], "MS")
		if j < 0 {
			break
		}
		j += i
		if j+width > len(data) {
			break
		}
		if data[j+1] == 'A' && (j == 0 || !isWordByte(data[j-1])) && (j+width == len(data) || !isWordByte(data[j+width])) && upperAlnum(data[j+2:j+width]) {
			out = append(out, data[j:j+width])
			i = j + width
			continue
		}
		i = j + 1
	}
	return out
}

func isWordByte(c byte) bool {
	return c == '_' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func upperAlnum(b []byte) bool {
	for _, c := range b {
		if !('0' <= c && c <= '9' || 'A' <= c && c <= 'Z') {
			return false
		}
	}
	return true
}
