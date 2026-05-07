// Package plivo detects Plivo Auth ID + Auth Token credentials — a paired
// detector. Auth IDs start with `MA` (master) or `SA` (subaccount) followed
// by 18 uppercase alphanumeric chars; tokens are >=40 base64url. Verified
// via /v1/Account/{auth_id}/ on api.plivo.com using HTTP Basic auth. Raw
// carries the auth_id, RawV2 carries the auth_token.
package plivo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.plivo.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// MA / SA + 18 uppercase alnum
var authIDRe = regexp.MustCompile(`\b((?:MA|SA)[A-Z0-9]{18})\b`)

// Auth tokens are 40+ base64url
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,128})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Plivo }

func (Scanner) Keywords() []string { return []string{"MA", "SA", "plivo"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := authIDRe.FindAllSubmatch(data, -1)
	if len(idHits) == 0 {
		return nil, nil
	}
	tHits := tokenRe.FindAllSubmatch(data, -1)
	if len(tHits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, idm := range idHits {
		authID := string(idm[1])
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
	return out, nil
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
