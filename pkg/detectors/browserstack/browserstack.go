// Package browserstack detects Browserstack username + access key pairs
// and verifies them against /automate/plan.json on api.browserstack.com
// with HTTP Basic auth (username + access key). Both halves co-occur near
// the `browserstack` keyword window. Stored as Raw=username, RawV2=access
// key (paired detector, like AWS / Razorpay / R2).
package browserstack

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.browserstack.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	// Browserstack usernames are alphanumeric, typically 8-24 chars; access
	// keys are exactly 20 chars (alnum) per current dashboard issuance.
	userRe = regexp.MustCompile(`(?i)browserstack[_\.\-]?user(?:name)?\s*[:=]\s*["']?([A-Za-z0-9_\-]{4,32})["']?`)
	keyRe  = regexp.MustCompile(`(?i)browserstack[_\.\-]?(?:access[_\.\-]?)?key\s*[:=]\s*["']?([A-Za-z0-9]{20})["']?`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Browserstack }

func (Scanner) Keywords() []string { return []string{"browserstack"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	users := userRe.FindAllSubmatch(data, -1)
	keys := keyRe.FindAllSubmatch(data, -1)
	if len(users) == 0 || len(keys) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(users))
	seen := map[string]struct{}{}
	for _, u := range users {
		username := string(u[1])
		for _, k := range keys {
			access := string(k[1])
			pair := username + ":" + access
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Browserstack,
				Raw:          []byte(username),
				RawV2:        []byte(access),
				Redacted:     redact(username),
				ExtraData:    map[string]string{"username": username},
			}
			if verify {
				v, err := s.verifyPair(ctx, username, access)
				res.Verified = v
				res.VerificationErr = err
			}
			out = append(out, res)
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify on the colon-joined form so the Verifier interface still works.
func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, username, access string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/automate/plan.json", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(username, access)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
