// Package twingate detects Twingate (twingate.com) API tokens (`tk_`
// prefix + colon/underscore-separated id + secret). Unverified-by-design
// — Twingate's GraphQL endpoint runs on a per-tenant host
// (`<network>.twingate.com/api/graphql/`) not present in the chunk;
// verify only fires when an apiBase override is supplied (test fakes).
package twingate

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is empty by default — verify is skipped unless overridden.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Twingate API tokens: tk_<32-base64url> or tkt_<...>.
var tokenRe = regexp.MustCompile(`\b(tkt?_[A-Za-z0-9_-]{20,200})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Twingate }

func (Scanner) Keywords() []string { return []string{"tk_", "tkt_"} }

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
			DetectorType: detectors.Twingate,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader(`{"query":"query { currentUser { id } }"}`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/api/graphql/", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-API-KEY", secret)
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
