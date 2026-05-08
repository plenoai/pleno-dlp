// Package qualys detects Qualys VMDR API username + password pairs near
// the `qualys` keyword. Unverified by design — Qualys routes per-region
// (`qualysapi.<region>.qualys.com`); verification fires only when an
// apiBase override is supplied.
package qualys

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

var userRe = regexp.MustCompile(`(?i)qualys[_\-]?user(?:name)?\s*[:=]\s*"?([A-Za-z0-9_\-]{4,64})"?`)
var passRe = regexp.MustCompile(`(?i)qualys[_\-]?pass(?:word)?\s*[:=]\s*"?([A-Za-z0-9_\-!@#$%^&*]{8,64})"?`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Qualys }

func (Scanner) Keywords() []string { return []string{"qualys"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	users := userRe.FindAllSubmatch(data, -1)
	if len(users) == 0 {
		return nil, nil
	}
	passes := passRe.FindAllSubmatch(data, -1)
	if len(passes) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, u := range users {
		user := string(u[1])
		for _, p := range passes {
			pass := string(p[1])
			pair := user + ":" + pass
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.Qualys,
				Raw:          []byte(user),
				RawV2:        []byte(pair),
				Redacted:     redact(user),
			}
			if verify && apiBase != "" {
				v, err := s.verifyPair(ctx, user, pass)
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

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	return s.verifyPair(ctx, parts[0], parts[1])
}

func (Scanner) verifyPair(ctx context.Context, user, pass string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/2.0/fo/session/?action=login", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(user, pass)
	req.Header.Set("X-Requested-With", "pleno-dlp")
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
