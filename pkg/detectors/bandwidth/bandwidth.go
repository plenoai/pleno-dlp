// Package bandwidth detects Bandwidth.com API credentials — a paired
// username + password (each 10+ alphanumeric) near the `bandwidth` keyword.
// Verified via /api/accounts on dashboard.bandwidth.com using HTTP Basic auth.
// Raw carries the username, RawV2 carries the password.
package bandwidth

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://dashboard.bandwidth.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{10,32})\b`)

// keywordRe is the anchored Bandwidth.com marker. The bare substring
// `bandwidth` is far too common in English prose (network bandwidth,
// `BandwidthLimitExceeded` in AWS retry docs, etc.) and pairs every
// nearby CamelCase ≥ 10-alnum word into a fake username/password. The
// regex demands a separator or a domain suffix so the keyword is
// unmistakably referring to Bandwidth.com credentials.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bbandwidth[_\-](?:api|user|username|pass(?:word)?|token|secret|key|account|id)\b` +
	`|\bbandwidth\.com\b` +
	`|\bdashboard\.bandwidth\.com\b` +
	`|\bbandwidth[ \t]*[:=]` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Bandwidth }

func (Scanner) Keywords() []string { return []string{"bandwidth"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for i, h := range hits {
		user := string(data[h[2]:h[3]])
		if _, dup := seen[user]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		var pass string
		for j, h2 := range hits {
			if j == i {
				continue
			}
			cand := string(data[h2[2]:h2[3]])
			if cand != user && nearKeyword(kwSpans, h2[2], h2[3]) {
				pass = cand
				break
			}
		}
		if pass == "" {
			continue
		}
		seen[user] = struct{}{}
		seen[pass] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Bandwidth,
			Raw:          []byte(user),
			RawV2:        []byte(pass),
			Redacted:     redact(user),
		}
		if verify {
			v, err := s.Verify(ctx, user+":"+pass)
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

// nearKeyword reports whether [start,end) is within the keyword radius
// of any anchored Bandwidth.com marker. Radius shrinks from the legacy
// 256 to 96 because credential lines (`BANDWIDTH_USER=…`) sit a handful
// of bytes from the marker, not on a different paragraph.
func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	user, pass := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/accounts", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)
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
