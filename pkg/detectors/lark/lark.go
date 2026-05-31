// Package lark detects Lark / Feishu Open Platform credentials — a paired
// app_id (`cli_<16 hex>`) + app_secret (32-char alphanumeric) near the `lark`
// / `feishu` keyword. Verified via /open-apis/auth/v3/tenant_access_token/internal
// on open.larksuite.com using JSON body. Raw carries the app_id, RawV2
// carries the app_secret.
package lark

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://open.larksuite.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var appIDRe = regexp.MustCompile(`\b(cli_[a-f0-9]{16})\b`)

// app_secret is a 32-char alphanumeric string with no prefix. Length and
// charset are authoritative from the upstream trufflehog larksuiteapikey
// detector (`[a-z0-9A-Z]{32}`):
// https://github.com/trufflesecurity/trufflehog/blob/main/pkg/detectors/larksuiteapikey/larksuiteapikey.go
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minSecretEntropy rejects 32-char runs that clear the regex but lack
// key-grade randomness (e.g. an MD5 hex digest or a repetitive build id near
// the keyword). 3.5 is safe for a 32-char high-variety base62 secret: real
// secrets clear ~4.5 (the dummy fixture measures 4.75) while degenerate runs
// fall well below.
const minSecretEntropy = 3.5

// contextRe is the windowed assignment-style arm regex. It replaces the prior
// bare strings.Contains(window,"lark"|"feishu"|"cli_") which matched any
// document merely mentioning Lark within 256 bytes. The bare keyword stays in
// Keywords() as the cheap prefilter.
var contextRe = regexp.MustCompile(`(?i)(lark|feishu)[_-]?(app[_-]?)?(id|secret|token|key)|cli_[a-f0-9]{16}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Lark }

func (Scanner) Keywords() []string { return []string{"cli_"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := appIDRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 {
		return nil, nil
	}
	secHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, h := range idHits {
		appID := string(data[h[2]:h[3]])
		if _, dup := seen[appID]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		var secret string
		for _, h2 := range secHits {
			cand := string(data[h2[2]:h2[3]])
			if strings.HasPrefix(cand, "cli_") {
				continue
			}
			// Entropy gate: a 32-char hex digest or repetitive run clears the
			// regex but is not a real app_secret. Real secrets are high-variety
			// base62 (~4.5 bits/char).
			if !detectors.HasMinEntropy(cand, minSecretEntropy) {
				continue
			}
			secret = cand
			break
		}
		if secret == "" {
			continue
		}
		seen[appID] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Lark,
			Raw:          []byte(appID),
			RawV2:        []byte(secret),
			Redacted:     redact(appID),
		}
		if verify {
			v, err := s.Verify(ctx, appID+":"+secret)
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
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	// Require an assignment-style Lark/Feishu credential marker (or the cli_
	// app_id shape) within the window, not a bare provider mention.
	return contextRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	appID, appSecret := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"app_id": appID, "app_secret": appSecret})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/open-apis/auth/v3/tenant_access_token/internal", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, nil
	}
	// Lark returns 200 with `code` field — non-zero `code` signals invalid creds.
	var out struct {
		Code int `json:"code"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, nil
	}
	return out.Code == 0, nil
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
