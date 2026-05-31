// Package elasticcloud detects Elastic Cloud / Elasticsearch API keys. The
// canonical encoded form is `<id>:<api_key>` base64-url, and the decoded form
// is colon-separated `<id>:<key>` where both halves are URL-safe base64.
//
// We accept both shapes and require co-occurrence with `elastic` /
// `elasticsearch` / `_security/_authenticate` in a 256-byte window because
// the `<base64>:<base64>` colon pair collides with arbitrary tokens.
//
// The matched `<id>:<key>` pair IS the Elasticsearch REST credential used in
// the `Authorization: ApiKey base64(id:key)` header, so it is verifiable
// against `GET /_security/_authenticate`. Elastic Cloud deployments live on
// per-customer https://<deployment>.<region>.cloud.es.io endpoints that are
// not present in the chunk, so Verify no-ops unless an apiBase override is
// supplied (class a per repo policy). Without apiBase it surfaces under
// --unverified-results.
package elasticcloud

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is empty by default: Elasticsearch clusters are per-customer hosts
// not derivable from the token, so live verification only fires when an
// operator supplies the deployment endpoint via apiBase override.
var apiBase = ""

var httpClient = &http.Client{Timeout: 5 * time.Second}

// id:secret pair, both URL-safe base64. Lengths chosen to match observed
// Elastic Cloud API keys (id ~20 chars, secret 22-43 chars).
var pairRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{16,32}):([A-Za-z0-9_-]{20,48})\b`)

var contextKeywords = []string{
	"elastic",
	"elasticsearch",
	"elastic_cloud",
	"_security/_authenticate",
	"apikey",
	"es_api_key",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ElasticCloud }

func (Scanner) Keywords() []string { return []string{"elastic", "elasticsearch"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := pairRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		id := string(data[h[2]:h[3]])
		secret := string(data[h[4]:h[5]])
		key := id + ":" + secret
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[key] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ElasticCloud,
			Raw:          []byte(id),
			RawV2:        []byte(secret),
			Redacted:     redact(id),
			ExtraData:    map[string]string{"api_key_id": id},
		}
		if verify {
			v, err := s.Verify(ctx, key)
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

// verify-coverage classification (verifyPlan):
//   - endpoint: GET /_security/_authenticate
//   - auth: Authorization: ApiKey base64(id:secret)
//   - 200 => valid; 401/403 => invalid; 429/5xx => transient (surfaced as err)
var (
	acceptCodes = []int{http.StatusOK}
	rejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

// Verify checks the Elasticsearch API key against GET /_security/_authenticate
// using the `Authorization: ApiKey base64(id:key)` scheme. The cluster host is
// per-customer and not in the chunk, so verification only fires when apiBase
// is overridden with the deployment endpoint. 200 => valid; 401/403 => invalid;
// 429 (rate limit) and 5xx (provider-side) are surfaced as transient errors via
// detectors.ClassifyVerifyHTTP so the engine never asserts validity ambiguously.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	if strings.Count(secret, ":") < 1 {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/_security/_authenticate", nil)
	if err != nil {
		return false, err
	}
	// Elasticsearch ApiKey auth: base64 of the decoded `id:key` pair.
	req.Header.Set("Authorization", "ApiKey "+base64.StdEncoding.EncodeToString([]byte(secret)))
	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, acceptCodes, rejectCodes)
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
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
