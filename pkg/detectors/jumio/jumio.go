// Package jumio detects Jumio (jumio.com) KYC API token + secret pairs
// near the `jumio` keyword. Unverified by design — Jumio uses
// per-data-center hosts (`netverify.com` / `lon.netverify.com` /
// `core-prod.jumio.ai`) that aren't in the chunk; verify only fires
// when an apiBase override is supplied. Raw=token, RawV2=token:secret
// per the trufflehog convention.
package jumio

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

var contextKeywords = []string{"jumio", "netverify"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jumio }

func (Scanner) Keywords() []string { return []string{"jumio", "netverify"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	if !contextHas(lower) {
		return nil, nil
	}
	var tokens []string
	seen := map[string]struct{}{}
	for _, h := range hits {
		t := string(data[h[2]:h[3]])
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		tokens = append(tokens, t)
		if len(tokens) == 2 {
			break
		}
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	key, secret := tokens[0], tokens[1]
	res := detectors.Result{
		DetectorType: detectors.Jumio,
		Raw:          []byte(key),
		RawV2:        []byte(key + ":" + secret),
		Redacted:     redact(key),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, key+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

func contextHas(lower string) bool {
	for _, kw := range contextKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/accounts", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("User-Agent", "pleno-dlp/jumio")
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
