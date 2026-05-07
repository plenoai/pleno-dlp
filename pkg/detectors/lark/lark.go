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
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

var contextKeywords = []string{"lark", "feishu"}

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
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	// Lark/Feishu credentials always carry the cli_ prefix in app_id, so the
	// keyword check is informational; accept either keyword or any cli_ prefix.
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return strings.Contains(window, "cli_")
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
