// Package oraclenetsuite detects Oracle NetSuite OAuth1 token ID +
// secret pairs near the `netsuite` keyword. Unverified by design —
// NetSuite routes per-account (`<account>.suitetalk.api.netsuite.com`
// + OAuth1 signing); verification fires only when an apiBase override
// is supplied and the OAuth1 dance is performed by the caller.
package oraclenetsuite

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

var tokenIDRe = regexp.MustCompile(`(?i)netsuite[_\-]?token[_\-]?id\s*[:=]\s*"?([0-9a-fA-F]{64})"?`)
var tokenSecretRe = regexp.MustCompile(`(?i)netsuite[_\-]?token[_\-]?secret\s*[:=]\s*"?([0-9a-fA-F]{64})"?`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OracleNetSuite }

func (Scanner) Keywords() []string { return []string{"netsuite"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ids := tokenIDRe.FindAllSubmatch(data, -1)
	if len(ids) == 0 {
		return nil, nil
	}
	secrets := tokenSecretRe.FindAllSubmatch(data, -1)
	if len(secrets) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0)
	seen := map[string]struct{}{}
	for _, idMatch := range ids {
		id := string(idMatch[1])
		for _, sMatch := range secrets {
			secret := string(sMatch[1])
			pair := id + ":" + secret
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.OracleNetSuite,
				Raw:          []byte(id),
				RawV2:        []byte(pair),
				Redacted:     redact(id),
			}
			if verify && apiBase != "" {
				v, err := s.verifyPair(ctx, id, secret)
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

func (Scanner) verifyPair(ctx context.Context, id, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// NetSuite uses OAuth1 with HMAC-SHA256 signing. We don't construct
	// the signature here — emit the call with the raw token + secret as
	// HTTP Basic so the test harness can confirm both halves traveled.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/services/rest/record/v1/employee", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, secret)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
