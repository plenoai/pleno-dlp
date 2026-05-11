// Package datadog detects Datadog API keys (32 hex) optionally paired with
// Application keys (40 hex), and verifies them via /api/v1/validate. On a
// verified pair the detector also queries /api/v1/api_key/<api> for the
// friendly name and creator metadata, and /api/v1/org for the org name —
// driftwood pattern: a leaked Datadog key labelled "production-monitor"
// in org "Acme Corp Production" is a different incident than one labelled
// "dev-test" in "Acme Sandbox". Triagers shouldn't have to issue a second
// API call to learn that.
package datadog

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.datadoghq.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// API key: 32 lowercase hex chars. Application key: 40 hex chars.
var (
	apiRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
	appRe = regexp.MustCompile(`\b([a-fA-F0-9]{40})\b`)
)

// Datadog candidates are extremely common shapes (md5, sha1) so the keyword
// gate is essential — only chunks that mention "datadog" or DD_ envs reach us.
type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Datadog }

func (Scanner) Keywords() []string {
	return []string{"datadog", "DD_API_KEY", "DD_APP_KEY", "DD_APPLICATION_KEY"}
}

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	apiHits := apiRe.FindAllSubmatchIndex(data, -1)
	if len(apiHits) == 0 {
		return nil, nil
	}
	appHits := appRe.FindAllSubmatchIndex(data, -1)

	out := make([]detectors.Result, 0, len(apiHits))
	seen := map[string]struct{}{}
	for _, m := range apiHits {
		api := string(data[m[2]:m[3]])
		if _, dup := seen[api]; dup {
			continue
		}
		seen[api] = struct{}{}
		app, ok := nearestApp(m[2], data, appHits)
		extra := map[string]string{}
		res := detectors.Result{
			DetectorType: detectors.Datadog,
			Raw:          []byte(api),
			Redacted:     redact(api),
			ExtraData:    extra,
		}
		if ok {
			res.RawV2 = []byte(app)
			if verify {
				v, meta, err := verifyPairWithMetadata(ctx, api, app)
				res.Verified = v
				res.VerificationErr = err
				for k, val := range meta {
					extra[k] = val
				}
			}
		}
		// Single-key (no app) candidates are emitted unverified so operators
		// see the surface area; they can pair manually if they have the app key.
		out = append(out, res)
	}
	return out, nil
}

// nearestApp picks the closest 40-hex match within 256 bytes of the api-key
// position. Same shape as the AWS detector's nearestSecret.
func nearestApp(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	// secret is expected as "<api>:<app>"; engine-level verify path packs
	// pairs the same way as AWS.
	api, app, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	v, _, err := verifyPairWithMetadata(ctx, api, app)
	return v, err
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPairWithMetadata(ctx context.Context, api, app string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/validate", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("DD-API-KEY", api)
	req.Header.Set("DD-APPLICATION-KEY", app)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		// fall through to enrichment
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil, nil
	default:
		return false, nil, nil
	}

	meta := map[string]string{}
	if name, creator := fetchAPIKeyName(ctx, api, app); name != "" || creator != "" {
		if name != "" {
			meta["dd_api_key_name"] = name
		}
		if creator != "" {
			meta["dd_api_key_created_by"] = creator
		}
	}
	if orgs := fetchOrgs(ctx, api, app); len(orgs) > 0 {
		// Single-org accounts are the common case; multi-org happens with
		// child organizations.
		names := make([]string, 0, len(orgs))
		for _, o := range orgs {
			if o.Name != "" {
				names = append(names, o.Name)
			}
		}
		sort.Strings(names)
		if len(names) > 0 {
			meta["dd_org_names"] = strings.Join(names, ",")
		}
		if len(orgs) > 0 && orgs[0].PublicID != "" {
			meta["dd_org_public_id"] = orgs[0].PublicID
		}
	}
	return true, meta, nil
}

// fetchAPIKeyName: GET /api/v1/api_key/<api> returns {api_key:{name,created_by,...}}.
// Requires read scope on api_keys for the application key.
func fetchAPIKeyName(ctx context.Context, api, app string) (name, creator string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/api_key/"+api, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("DD-API-KEY", api)
	req.Header.Set("DD-APPLICATION-KEY", app)
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", ""
	}
	var body struct {
		APIKey struct {
			Name      string `json:"name"`
			CreatedBy string `json:"created_by"`
		} `json:"api_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", ""
	}
	return body.APIKey.Name, body.APIKey.CreatedBy
}

type ddOrg struct {
	Name     string `json:"name"`
	PublicID string `json:"public_id"`
}

// fetchOrgs: GET /api/v1/org returns the orgs the app key can see.
func fetchOrgs(ctx context.Context, api, app string) []ddOrg {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/api/v1/org", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("DD-API-KEY", api)
	req.Header.Set("DD-APPLICATION-KEY", app)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var body struct {
		Orgs []ddOrg `json:"orgs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil
	}
	return body.Orgs
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
