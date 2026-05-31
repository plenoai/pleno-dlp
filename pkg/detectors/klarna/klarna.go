// Package klarna detects Klarna API credentials and verifies them against
// /payments/v1/sessions on api.klarna.com using HTTP Basic auth.
//
// Klarna's current credential model issues an API key (used as the Basic-auth
// password) that carries a distinguishing prefix:
//
//	klarna_<live|test>_api_<random>
//
// e.g. klarna_live_api_<RANDOM> where the random tail is a base64-ish run of
// letters, digits, and symbols. The full key may be up to 255 characters.
// The matching username displayed alongside it in the merchant portal is a
// UUID. Sources:
//   - https://docs.klarna.com/api-reference/authentication/  (key format
//     `klarna_<live|test>_api_<random>`; sent as `Authorization: Basic <key>`)
//   - https://docs.klarna.com/api/authentication/  (username "in the form of a
//     UUID is displayed together with the API key")
//   - https://www.drupal.org/project/commerce_klarna_payments/issues/3499488
//     (portal-downloaded password carries the `klarna_live_api_` prefix and may
//     be up to 255 chars)
//
// Anchoring on the `klarna_(live|test)_api_` prefix is the discriminator, so no
// entropy floor is needed. The UUID username, when present nearby, is paired in
// for the Basic-auth verification.
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

// keyRe anchors on the documented `klarna_(live|test)_api_` prefix. The random
// tail is base64-ish (letters, digits, +/=*_- and similar); the whole key may
// run up to 255 chars, so we cap the tail at 240 to stay under that bound while
// the prefix carries the discrimination.
var keyRe = regexp.MustCompile(`klarna_(?:live|test)_api_[A-Za-z0-9+/=*_-]{16,240}`)

// uuidRe captures the merchant-portal username (a UUID) when it sits near the
// key, so the pair can be sent to Basic auth. Optional — the key alone is the
// detection.
var uuidRe = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

// contextRe is the windowed assignment-anchor gate within radius 64. The bare
// keyword "klarna" stays in Keywords() as the engine prefilter; here we require
// an assignment-shaped klarna credential reference so prose mentions of the
// word do not arm the detector.
var contextRe = regexp.MustCompile(`(?i)klarna[_-]?(api[_-]?)?(token|key|secret|user|pass(word)?|cred(ential)?s?)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Klarna }

func (Scanner) Keywords() []string { return []string{"klarna"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	keyHits := keyRe.FindAllIndex(data, -1)
	if len(keyHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(keyHits))
	seen := map[string]struct{}{}
	for _, h := range keyHits {
		key := string(data[h[0]:h[1]])
		if _, dup := seen[key]; dup {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[key] = struct{}{}
		// The key already embeds live/test discrimination; a UUID username, when
		// present anywhere in the chunk, completes the Basic-auth pair.
		user := uuidRe.FindString(string(data))
		res := detectors.Result{
			DetectorType: detectors.Klarna,
			Raw:          []byte(key),
			Redacted:     redact(key),
		}
		if user != "" {
			res.RawV2 = []byte(user + ":" + key)
		}
		if verify {
			v, err := s.Verify(ctx, user+":"+key)
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
	return contextRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	user, pass, ok := strings.Cut(secret, ":")
	if !ok {
		// No UUID username found; Klarna Basic auth needs the username half.
		return false, nil
	}
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
	if len(t) <= 16 {
		return t
	}
	return t[:16] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
