// Package frontegg detects FrontEgg client secrets. FrontEgg vendor secrets
// are UUIDs paired with a vendor client_id. Gated on `frontegg` keyword
// window because UUID alone has too many false positives. Verified via
// /auth/vendor on api.frontegg.com using a paired client_id+secret JSON
// body — read-only.
package frontegg

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.frontegg.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	clientIDRe = regexp.MustCompile(`(?i)frontegg[_\.\-]?(?:client[_\.\-]?id|vendor[_\.\-]?id)\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`)
	secretRe   = regexp.MustCompile(`(?i)frontegg[_\.\-]?(?:client[_\.\-]?secret|api[_\.\-]?secret|secret)\s*[:=]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.FrontEgg }

func (Scanner) Keywords() []string { return []string{"frontegg"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	ids := clientIDRe.FindAllSubmatch(data, -1)
	secrets := secretRe.FindAllSubmatch(data, -1)
	if len(ids) == 0 || len(secrets) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(ids))
	seen := map[string]struct{}{}
	for _, id := range ids {
		cid := string(id[1])
		for _, sec := range secrets {
			csec := string(sec[1])
			pair := cid + ":" + csec
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			res := detectors.Result{
				DetectorType: detectors.FrontEgg,
				Raw:          []byte(cid),
				RawV2:        []byte(csec),
				Redacted:     redact(cid),
			}
			if verify {
				v, err := s.verifyPair(ctx, cid, csec)
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

func (Scanner) verifyPair(ctx context.Context, cid, csec string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	body, _ := json.Marshal(map[string]string{"clientId": cid, "secret": csec})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiBase+"/auth/vendor/", bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusTooManyRequests:
		return false, nil
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
