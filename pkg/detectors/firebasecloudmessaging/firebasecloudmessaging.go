// Package firebasecloudmessaging detects FCM legacy server keys — `AAAA`-
// prefixed base64url tokens near `fcm` / `firebase` keywords. Verified via
// /fcm/send on fcm.googleapis.com using `Authorization: key=<token>`. A 200
// or 400 (bad payload) response with the key in the auth header confirms
// validity; 401 means the key is rejected.
package firebasecloudmessaging

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://fcm.googleapis.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// FCM legacy server keys: `AAAA<base64url>:APA91b<base64url>` — the prefix
// `AAAA` is followed by base64url chars and a colon-separated `APA91b`
// identifier. We capture the entire token shape.
var tokenRe = regexp.MustCompile(`\b(AAAA[A-Za-z0-9_-]{7}:APA91b[A-Za-z0-9_-]{134,200})\b`)

var contextKeywords = []string{"fcm", "firebase", "firebase_server_key", "firebase_messaging"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.FirebaseCloudMessaging }

func (Scanner) Keywords() []string { return []string{"fcm", "firebase", "AAAA"} }

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
			DetectorType: detectors.FirebaseCloudMessaging,
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/fcm/send", strings.NewReader(`{}`))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "key="+secret)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK, http.StatusBadRequest:
		// 400 = key valid but body malformed; treat as verified.
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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
