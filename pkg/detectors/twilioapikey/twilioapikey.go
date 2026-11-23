// Package twilioapikey detects Twilio API key SIDs (`SK` + 32 hex) and
// pairs each with the nearest 32-character API key secret. A pair is
// verified with HTTP Basic auth against /2010-04-01/Accounts.json, which
// lists the accounts the key may act on. A SID without a nearby secret
// is still reported (unverified) so the operator can revoke it.
package twilioapikey

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.twilio.com"

var httpClient = detectors.NewVerifyHTTPClient(10 * time.Second)

var (
	sidRe    = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`) })
	secretRe = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`) })
)

// maxPairDistance bounds how far (bytes) a secret may sit from its SID.
const maxPairDistance = 256

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.TwilioAPIKey }

func (Scanner) Keywords() []string { return []string{"SK"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	if !bytes.Contains(data, []byte("SK")) {
		return nil, nil
	}
	sids := sidRe().FindAllSubmatchIndex(data, -1)
	if len(sids) == 0 {
		return nil, nil
	}
	secrets := secretRe().FindAllSubmatchIndex(data, -1)
	out := make([]detectors.Result, 0, len(sids))
	seen := map[string]struct{}{}
	for _, m := range sids {
		sid := string(data[m[2]:m[3]])
		if _, dup := seen[sid]; dup {
			continue
		}
		seen[sid] = struct{}{}
		res := detectors.Result{DetectorType: detectors.TwilioAPIKey, Raw: []byte(sid), Redacted: redact(sid)}
		if secret, ok := nearestSecret(data, m, secrets); ok {
			res.RawV2 = []byte(secret)
			if verify {
				res.Verified, res.VerificationErr = verifyPair(ctx, sid, secret)
			}
		}
		out = append(out, res)
	}
	return detectors.SafeResults(out), nil
}

// nearestSecret picks the closest secret candidate that is not part of a
// SID and carries both a digit and a letter (a 32-char all-letter word is
// almost always an identifier).
func nearestSecret(data []byte, sid []int, hits [][]int) (string, bool) {
	best, bestDist := "", maxPairDistance+1
	for _, h := range hits {
		start, end := h[2], h[3]
		if start >= sid[2] && end <= sid[3] {
			continue
		}
		cand := data[start:end]
		if !bytes.ContainsAny(cand, "0123456789") || bytes.IndexFunc(cand, isLetter) < 0 {
			continue
		}
		if sidRe().Match(cand) {
			continue
		}
		dist := start - sid[2]
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			best, bestDist = string(cand), dist
		}
	}
	return best, best != ""
}

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// Verify accepts "SK…:secret".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	sid, sec, ok := strings.Cut(secret, ":")
	if !ok || sid == "" || sec == "" {
		return false, nil
	}
	return verifyPair(ctx, sid, sec)
}

func verifyPair(ctx context.Context, sid, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/2010-04-01/Accounts.json?PageSize=1", nil)
	if err != nil {
		return false, fmt.Errorf("twilio api key verify: build request")
	}
	req.SetBasicAuth(sid, secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("twilio api key verify: request failed")
	}
	defer resp.Body.Close()
	return detectors.ClassifyVerifyHTTP(resp, nil, []int{http.StatusOK}, []int{http.StatusUnauthorized, http.StatusForbidden})
}

func (Scanner) MaxVerificationAssurance() detectors.VerificationAssurance {
	return detectors.AssuranceProviderConfirmed
}

func redact(sid string) string { return sid[:6] + "..." }

var (
	_ detectors.Verifier           = Scanner{}
	_ detectors.VerificationPolicy = Scanner{}
)

func init() { detectors.Register(Scanner{}) }
