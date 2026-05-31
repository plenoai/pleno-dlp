// Package eloqua detects Oracle Eloqua REST API client_id + client_secret
// pairs near an `eloqua`-prefixed assignment. Verified via
// /api/REST/2.0/system/user/current on the per-pod host
// (`secure.p<NN>.eloqua.com`). Unverified-by-default — the pod host isn't in
// the chunk; verify only fires when an apiBase override is supplied. Raw
// carries the client_id, RawV2 the secret.
//
// FP-hardening research note: Oracle's auth docs
// (docs.oracle.com/en/cloud/saas/marketing/eloqua-rest-api/Authentication_Auth.html
// and the AppCloud OAuth guide) describe only the HTTP-Basic
// base64(client_id:client_secret) flow and use generic RFC-6749 placeholders
// (`a1b2c3d4`, `s6BhdRkqt3`); they do NOT document the length, charset, or any
// prefix of the credentials. Trufflehog has no upstream eloqua detector to
// mirror. No authoritative format found — conservative gate-tightening only:
// radius 256->64, bare strings.Contains replaced by an assignment-anchor arm
// regex, and a conservative HasMinEntropy(token, 3.0) floor. The token length
// range is intentionally left wide so recall is not destroyed by an unverified
// length pin.
package eloqua

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

// Oracle does not publicly document the length, charset, or any prefix of the
// Eloqua OAuth Client Id / Client Secret (the auth docs only describe the
// HTTP-Basic base64(client_id:client_secret) flow and use generic RFC-6749
// placeholders like `a1b2c3d4`). With no authoritative format to pin, this
// stays a wide alphanumeric range and the gate carries the FP load. See the
// research note in the package-level doc comment.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{24,128})\b`)

// armRe is the assignment-style Eloqua reference that must appear within the
// proximity window. A bare "eloqua" substring (doc links, the per-pod
// `secure.pNN.eloqua.com` host, dependency names) is far too weak a gate
// against a generic 24-128 alphanumeric run; the shape an actual credential
// assignment or config key takes is `eloqua[_-]?(client[_-]?)?(id|secret|token|key)`.
var armRe = regexp.MustCompile(`(?i)eloqua[_\-]?(client[_\-]?)?(id|secret|token|key)`)

// minEntropy rejects low-entropy 24-128 char runs that clear the alnum regex
// but are not random credentials (e.g. padded placeholders, repeated runs).
// 3.0 is a conservative floor (no documented length/charset to justify 3.5).
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Eloqua }

func (Scanner) Keywords() []string { return []string{"eloqua"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if _, dup := seen[v]; dup {
			continue
		}
		// Entropy gate: structured/low-information 24-128 char runs (e.g. a
		// padded placeholder or a long run of repeated characters) clear the
		// alnum regex but are not random credentials — reject even when armed.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	id, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.Eloqua,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, id+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether an `eloqua[_-]?(client[_-]?)?(id|secret|token|key)`
// reference appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so an id and a
// secret defined alongside nearby ELOQUA_CLIENT_ID / ELOQUA_CLIENT_SECRET
// references still arm.
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
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	if apiBase == "" {
		return false, nil
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/REST/2.0/system/user/current", nil)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
	req.Header.Set("Accept", "application/json")
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
