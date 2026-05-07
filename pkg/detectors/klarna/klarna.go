// Package klarna detects Klarna API credentials — a paired username (Klarna
// uses `PK<digits>_<8>` for production, `PK_test_<digits>_<8>` for sandbox)
// and a 32-64 char password near the `klarna` keyword. Verified via
// /payments/v1/sessions on api.klarna.com using HTTP Basic auth.
package klarna

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.klarna.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var userRe = regexp.MustCompile(`\b(PK(?:_test)?[0-9]{4,}_[A-Z0-9]{6,})\b`)
var passRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

var contextKeywords = []string{"klarna"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Klarna }

func (Scanner) Keywords() []string { return []string{"PK"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	userHits := userRe.FindAllSubmatchIndex(data, -1)
	if len(userHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, h := range userHits {
		user := string(data[h[2]:h[3]])
		if _, dup := seen[user]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Find a password candidate that is not the username itself.
		passHits := passRe.FindAllSubmatch(data, -1)
		var password string
		for _, ph := range passHits {
			cand := string(ph[1])
			if cand == user || strings.HasPrefix(cand, "PK") {
				continue
			}
			password = cand
			break
		}
		if password == "" {
			continue
		}
		seen[user] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Klarna,
			Raw:          []byte(user),
			RawV2:        []byte(password),
			Redacted:     redact(user),
		}
		if verify {
			v, err := s.Verify(ctx, user+":"+password)
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	user, pass := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Minimal sessions create — Klarna returns 200 / 401 / 403.
	body := bytes.NewReader([]byte(`{"purchase_country":"US","purchase_currency":"USD","locale":"en-US","order_amount":0,"order_lines":[]}`))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/payments/v1/sessions", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusBadRequest:
		// 400 with valid auth means "your auth was accepted; payload was
		// malformed" — that's positive verification of the credential pair.
		return true, nil
	default:
		return false, nil
	}
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
