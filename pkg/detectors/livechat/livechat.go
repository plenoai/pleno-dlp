// Package livechat detects LiveChat (livechat.com) personal access
// tokens (`dal:` prefix + colon-separated id/secret) near the livechat
// keyword. Verified via /v3.5/agent/action/list_my_profiles on
// api.livechatinc.com with Authorization Bearer header.
package livechat

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.livechatinc.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// LiveChat PAT shape: dal:<account-id>:<secret> (id is uuid-ish, secret is base64url).
var tokenRe = regexp.MustCompile(`\b(dal:[A-Za-z0-9_-]{6,40}:[A-Za-z0-9_-]{20,80})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LiveChat }

func (Scanner) Keywords() []string { return []string{"dal:"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.LiveChat,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v3.5/agent/action/list_my_profiles", strings.NewReader("{}"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
