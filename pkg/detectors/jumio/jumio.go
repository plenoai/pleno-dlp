// Package jumio detects Jumio (jumio.com) KYC API token + secret pairs
// near the `jumio` keyword. Unverified by design — Jumio uses
// per-data-center hosts (`netverify.com` / `lon.netverify.com` /
// `core-prod.jumio.ai`) that aren't in the chunk; verify only fires
// when an apiBase override is supplied. Raw=token, RawV2=token:secret
// per the trufflehog convention.
//
// Hardening: the raw `[A-Za-z0-9]{32,64}` token regex matches almost any
// hex/base64-ish blob (asset hashes, UUIDs concatenations, git SHAs,
// JWT segments), so a whole-file `Contains("jumio")` gate that grabbed
// the first two blobs produced heavy false positives. We now require an
// assignment-style Jumio reference (`jumio_api_token=`, `jumio-secret:`,
// …) within a tight window before each candidate token and gate every
// token on Shannon entropy. The first two distinct armed+high-entropy
// tokens are paired as key:secret per the original RawV2 semantics.
package jumio

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// anchorRe is the assignment-style Jumio reference that must appear in the
// proximityRadius bytes preceding a candidate token. Matching this rather
// than a stray `jumio` substring anywhere in the chunk is what kills the
// false positives from co-occurring asset hashes / UUIDs.
var anchorRe = regexp.MustCompile(`jumio[_\-]?(?:api[_\-]?(?:token|secret|key)|token|secret)\s*[:=]`)

// minEntropy rejects low-entropy runs (repeated chars, zero-padded blobs,
// structured-but-non-random alnum) that clear the length floor but are
// not credentials. base64url/alnum tokens sit well above this.
const minEntropy = 3.5

// proximityRadius is the number of bytes BEFORE the token within which an
// assignment-style Jumio reference must appear.
const proximityRadius = 64

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Jumio }

func (Scanner) Keywords() []string { return []string{"jumio", "netverify"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var tokens []string
	seen := map[string]struct{}{}
	for _, h := range hits {
		t := string(data[h[2]:h[3]])
		if _, dup := seen[t]; dup {
			continue
		}
		// Entropy gate: structured/repeated alnum without real randomness
		// is rejected before it can be paired.
		if !detectors.HasMinEntropy(t, minEntropy) {
			continue
		}
		// Require an assignment-style Jumio reference in a tight window
		// before the token, not a stray "jumio" substring in the chunk.
		if !armedByAnchor(lower, h[2]) {
			continue
		}
		seen[t] = struct{}{}
		tokens = append(tokens, t)
		if len(tokens) == 2 {
			break
		}
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	key, secret := tokens[0], tokens[1]
	res := detectors.Result{
		DetectorType: detectors.Jumio,
		Raw:          []byte(key),
		RawV2:        []byte(key + ":" + secret),
		Redacted:     redact(key),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, key+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// armedByAnchor reports whether an assignment-style Jumio reference appears
// in the proximityRadius bytes immediately preceding the token.
func armedByAnchor(lower string, start int) bool {
	from := start - proximityRadius
	if from < 0 {
		from = 0
	}
	window := lower[from:start]
	return anchorRe.MatchString(window)
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v1/accounts", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
	req.Header.Set("User-Agent", "pleno-dlp/jumio")
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
