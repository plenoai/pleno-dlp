// Package cloudinary detects Cloudinary URL credentials of shape
// `cloudinary://<api_key>:<api_secret>@<cloud_name>`. This format embeds
// all three parts (key, secret, cloud name) so verification is feasible —
// performed via /v1_1/<cloud>/usage on api.cloudinary.com using HTTP Basic
// auth (key as username, secret as password). The keyword `cloudinary` is
// implicit in the URL scheme.
package cloudinary

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.cloudinary.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var urlRe = regexp.MustCompile(`cloudinary://([0-9]{6,18}):([A-Za-z0-9_\-]{20,80})@([A-Za-z0-9_\-]{2,64})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType         { return detectors.Cloudinary }
func (Scanner) VerificationCacheUsesFullInput() bool { return true }

func (Scanner) Keywords() []string { return []string{"cloudinary"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := urlRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		key := string(h[1])
		secret := string(h[2])
		cloud := string(h[3])
		joined := key + ":" + secret + "@" + cloud
		if _, dup := seen[joined]; dup {
			continue
		}
		seen[joined] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Cloudinary,
			Raw:          []byte(key),
			RawV2:        []byte(secret),
			Redacted:     redact(secret),
			ExtraData:    map[string]string{"cloud_name": cloud},
		}
		if verify {
			v, err := s.verify(ctx, key, secret, cloud)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	// secret expected as "<key>:<secret>@<cloud>"
	colonIdx := strings.Index(secret, ":")
	atIdx := strings.LastIndex(secret, "@")
	if colonIdx < 0 || atIdx < 0 || colonIdx >= atIdx {
		return false, nil
	}
	return s.verify(ctx, secret[:colonIdx], secret[colonIdx+1:atIdx], secret[atIdx+1:])
}

func (Scanner) verify(ctx context.Context, key, secret, cloud string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1_1/"+cloud+"/usage", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(key, secret)
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
