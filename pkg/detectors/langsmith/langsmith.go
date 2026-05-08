// Package langsmith detects LangSmith (smith.langchain.com) API keys
// (`lsv2_(pt|sk)_` prefix + 40-char hex). Verified via /info on
// api.smith.langchain.com with x-api-key header.
package langsmith

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.smith.langchain.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b(lsv2_(?:pt|sk)_[a-f0-9]{32,64}_[a-f0-9]{8,16})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LangSmith }

func (Scanner) Keywords() []string { return []string{"lsv2_pt_", "lsv2_sk_"} }

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
			DetectorType: detectors.LangSmith,
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/info", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("x-api-key", secret)
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
