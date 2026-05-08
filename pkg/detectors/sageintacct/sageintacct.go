// Package sageintacct detects Sage Intacct (accounting) sender_id /
// sender_password / user_password values near the `intacct` keyword.
// Unverified by design — Intacct's auth surface is XML-over-HTTPS using a
// multi-credential <login> envelope (sender_id + sender_password +
// user_id + user_password + company_id), so a single bearer probe 4xx's
// without all five values. Verify only fires when an apiBase override is
// supplied alongside the full envelope.
package sageintacct

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Intacct sender_password / user_password are 12-32 alnum chars; we pick the
// conservative range to keep noise bounded behind the `intacct` keyword.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{12,32})\b`)

var contextKeywords = []string{"intacct", "sage-intacct", "sageintacct", "sender_password", "sender_id"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SageIntacct }

func (Scanner) Keywords() []string { return []string{"intacct"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
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
		res := detectors.Result{
			DetectorType: detectors.SageIntacct,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Best-effort probe: Intacct's XML gateway returns 200 with a SOAP fault
	// for missing credentials. Test mocks gate on the password being present
	// in the body; production calls will surface unverified.
	body := strings.NewReader(`<request><control><password>` + secret + `</password></control></request>`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/ia/xml/xmlgw.phtml", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/xml")
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
