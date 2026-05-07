// Package twilio detects Twilio Account SID + Auth Token pairs and verifies
// them against /2010-04-01/Accounts/<sid>.json.
package twilio

import (
	"context"
	"net/http"
	"regexp"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.twilio.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// SID: AC + 32 hex. Auth token: 32 hex (no provider prefix, so we always
// require pairing with a SID to emit verified=true).
var (
	sidRe   = regexp.MustCompile(`\b(AC[a-f0-9]{32})\b`)
	tokenRe = regexp.MustCompile(`\b([a-f0-9]{32})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Twilio }

func (Scanner) Keywords() []string { return []string{"AC", "twilio"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	sids := sidRe.FindAllSubmatchIndex(data, -1)
	if len(sids) == 0 {
		return nil, nil
	}
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	// The 32-hex tail of every SID also matches tokenRe; filter those out so
	// we don't pair a SID with its own tail.
	tokens = excludeOverlap(tokens, sids)

	out := make([]detectors.Result, 0, len(sids))
	seen := map[string]struct{}{}
	for _, m := range sids {
		sid := string(data[m[2]:m[3]])
		if _, dup := seen[sid]; dup {
			continue
		}
		seen[sid] = struct{}{}
		token, ok := nearestToken(m[2], data, tokens)
		res := detectors.Result{
			DetectorType: detectors.Twilio,
			Raw:          []byte(sid),
			Redacted:     redact(sid),
			ExtraData:    map[string]string{"account_sid": sid},
		}
		if ok {
			res.RawV2 = []byte(token)
			if verify {
				v, err := verifyPair(ctx, sid, token)
				res.Verified = v
				res.VerificationErr = err
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func excludeOverlap(tokens, sids [][]int) [][]int {
	if len(sids) == 0 {
		return tokens
	}
	out := tokens[:0]
	for _, t := range tokens {
		ts, te := t[2], t[3]
		drop := false
		for _, s := range sids {
			ss, se := s[2], s[3]
			// SID's hex tail starts at ss+2 and ends at se. Drop tokens that
			// fall inside that window.
			if ts >= ss+2 && te <= se {
				drop = true
				break
			}
		}
		if !drop {
			out = append(out, t)
		}
	}
	return out
}

func nearestToken(idStart int, data []byte, hits [][]int) (string, bool) {
	const maxDistance = 256
	bestDist := maxDistance + 1
	best := ""
	for _, h := range hits {
		start, end := h[2], h[3]
		dist := abs(start - idStart)
		if dist < bestDist {
			bestDist = dist
			best = string(data[start:end])
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	sid, token, ok := splitPair(secret)
	if !ok {
		return false, nil
	}
	return verifyPair(ctx, sid, token)
}

func splitPair(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func verifyPair(ctx context.Context, sid, token string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/2010-04-01/Accounts/"+sid+".json", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(sid, token)

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

func redact(sid string) string {
	if len(sid) <= 6 {
		return sid
	}
	return sid[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
