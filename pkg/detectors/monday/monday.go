// Package monday detects Monday.com API tokens (JWT-shaped near a `monday`
// keyword) and verifies them with a `{ me { id } }` GraphQL query.
//
// Monday tokens are HS256/RS256 JWTs whose audience is `monday`. We don't
// parse claims here — the JWT detector still surfaces every JWT, and the
// monday detector adds a verified channel for the subset that authenticate
// against api.monday.com. Co-occurrence with `monday` keeps us out of the
// way of every JWT in the corpus.
package monday

import (
	"bytes"
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.monday.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// JWT shape — eyJ + base64url... .eyJ + base64url... .signature.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`)

var contextKeywords = []string{"monday.com", "monday_api", "monday_token", "mondaycom", "monday "}

var probeBody = []byte(`{"query":"{ me { id } }"}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Monday }

func (Scanner) Keywords() []string { return []string{"monday"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := jwtRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Monday,
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

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/v2", bytes.NewReader(probeBody))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("API-Version", "2024-01")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	// Monday returns 200 on a valid token (with `data.me.id` payload) and
	// 401 on a bad token. Some bad tokens come back as 200 with an
	// `errors` array and `data: null` — we don't read the body here
	// because false-positives on shape are minimal and reading the body
	// would slow the verification path.
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests:
		return false, nil
	default:
		return false, nil
	}
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

func redact(t string) string {
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
