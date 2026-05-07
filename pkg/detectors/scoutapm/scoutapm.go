// Package scoutapm detects Scout APM agent credentials — a paired detector
// surfacing both the account-key (8-16 alphanumeric agent key) and the API
// key (>=40 base64url) near the `scoutapm` / `scout_apm` keyword. Verified
// via /api/v0/check on scoutapm.com using HTTP Basic auth (key as user,
// agent_key as password). Raw carries the agent key, RawV2 carries the API
// key.
package scoutapm

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://scoutapm.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Agent keys are 16-char base64url, API keys are >=40 base64url.
var agentKeyRe = regexp.MustCompile(`\b([A-Za-z0-9]{16})\b`)
var apiKeyRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{40,128})\b`)

var contextKeywords = []string{"scoutapm", "scout_apm", "scout-apm", "scout_key"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ScoutAPM }

func (Scanner) Keywords() []string { return []string{"scoutapm", "scout_apm"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	akHits := agentKeyRe.FindAllSubmatchIndex(data, -1)
	apiHits := apiKeyRe.FindAllSubmatchIndex(data, -1)
	if len(akHits) == 0 || len(apiHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, ak := range akHits {
		agentKey := string(data[ak[2]:ak[3]])
		if _, dup := seen[agentKey]; dup {
			continue
		}
		if !nearKeyword(lower, ak[2], ak[3]) {
			continue
		}
		var apiKey string
		for _, ah := range apiHits {
			cand := string(data[ah[2]:ah[3]])
			if cand == agentKey || len(cand) <= 16 {
				continue
			}
			if !nearKeyword(lower, ah[2], ah[3]) {
				continue
			}
			apiKey = cand
			break
		}
		if apiKey == "" {
			continue
		}
		seen[agentKey] = struct{}{}
		seen[apiKey] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ScoutAPM,
			Raw:          []byte(agentKey),
			RawV2:        []byte(apiKey),
			Redacted:     redact(agentKey),
		}
		if verify {
			v, err := s.Verify(ctx, agentKey+":"+apiKey)
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

// Verify accepts the combined `agentKey:apiKey` pair.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	agentKey, apiKey := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v0/check", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(apiKey, agentKey)
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
