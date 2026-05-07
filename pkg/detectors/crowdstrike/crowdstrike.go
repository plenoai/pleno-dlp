// Package crowdstrike detects CrowdStrike Falcon API client_id +
// client_secret pairs. CrowdStrike issues OAuth2 client credentials of shape
// 32-hex client_id and 40-char alnum client_secret. Both halves co-occur near
// the `crowdstrike` keyword window. Verified via /oauth2/token on
// api.crowdstrike.com using client_credentials grant.
package crowdstrike

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.crowdstrike.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	clientIDRe     = regexp.MustCompile(`(?i)(?:client[_\.\-]?id|falcon[_\.\-]?client[_\.\-]?id)\s*[:=]\s*["']?([a-f0-9]{32})["']?`)
	clientSecretRe = regexp.MustCompile(`(?i)(?:client[_\.\-]?secret|falcon[_\.\-]?client[_\.\-]?secret)\s*[:=]\s*["']?([A-Za-z0-9]{40})["']?`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CrowdStrike }

func (Scanner) Keywords() []string { return []string{"crowdstrike"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !strings.Contains(strings.ToLower(string(data)), "crowdstrike") {
		return nil, nil
	}
	ids := clientIDRe.FindAllSubmatch(data, -1)
	secrets := clientSecretRe.FindAllSubmatch(data, -1)
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		cid := string(id[1])
		for _, sec := range secrets {
			cs := string(sec[1])
			pair := cid + ":" + cs
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.CrowdStrike,
				Raw:          []byte(cid),
				RawV2:        []byte(cs),
				Redacted:     redact(cid),
			}
			if verify {
				v, err := s.verifyPair(ctx, cid, cs)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, cid, cs string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	form := url.Values{}
	form.Set("client_id", cid)
	form.Set("client_secret", cs)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusBadRequest:
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
