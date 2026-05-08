// Package mandiant detects Mandiant Advantage API key + secret pairs
// near the `mandiant` / `fireeye` keyword. Verified via /token (OAuth
// client_credentials) on api.intelligence.fireeye.com using HTTP Basic
// auth (key as username, secret as password). Raw=key, RawV2=key:secret
// per the trufflehog convention for paired credentials.
package mandiant

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.intelligence.fireeye.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Mandiant API keys and secret IDs are 32-64 alnum chars each. We match
// each independently then pair them within the chunk if both appear
// near the keyword.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

var contextKeywords = []string{"mandiant", "fireeye", "intelligence.fireeye"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mandiant }

func (Scanner) Keywords() []string { return []string{"mandiant", "fireeye"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	// Collect the first two keyword-adjacent unique tokens — Mandiant
	// distributes credentials as a pair (api_key + secret_id) and they
	// almost always appear in the same chunk near `mandiant`.
	var tokens []string
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		tokens = append(tokens, token)
		if len(tokens) == 2 {
			break
		}
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	key, secret := tokens[0], tokens[1]
	res := detectors.Result{
		DetectorType: detectors.Mandiant,
		Raw:          []byte(key),
		RawV2:        []byte(key + ":" + secret),
		Redacted:     redact(key),
	}
	if verify {
		v, err := s.Verify(ctx, key+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
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

// Verify expects secret formatted as "key:secret".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&scope=appliance.collector")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/token", body)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
