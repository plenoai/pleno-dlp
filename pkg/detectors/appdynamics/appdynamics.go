// Package appdynamics detects AppDynamics API client + secret pairs near
// the `appdynamics` keyword. Verified via /controller/api/oauth/access_token
// on the per-controller host (`<acct>.saas.appdynamics.com`) using
// HTTP Basic auth with `<api_client>@<account>:<secret>`. The controller
// host isn't carried in the chunk so verify requires apiBase override and
// ships unverified-by-default. Raw carries the api_client@account, RawV2
// carries the secret.
package appdynamics

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase overrides the verify host. Default empty disables verify.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// `<api_client>@<account>` — both parts are alnum / underscore / hyphen.
var clientRe = regexp.MustCompile(`\b([A-Za-z0-9_-]{3,32}@[A-Za-z0-9_-]{3,64})\b`)

// secretRe pins the documented API Client Secret shape. AppDynamics
// "Generate Secret" produces a UUID (e.g. face10d5-573e-4a75-8396-afa006fd8f19);
// it is canonical lowercase 8-4-4-4-12 hex. Source: Splunk AppDynamics "API
// Clients" docs — "This will generate a UUID as the secret of the API Client."
// The prior bare [A-Za-z0-9]{20,64} matched any 20-64 char alnum run, a heavy
// false-positive source; pinning the UUID layout fixes the length implicitly.
var secretRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

// armRe is the assignment-style AppDynamics reference that must appear within
// the proximity window. A bare "appdynamics"/"appd" substring (doc links, the
// per-controller `<acct>.saas.appdynamics.com` host, log lines) is too weak a
// gate; `appd(ynamics)?[_-]?(api[_-]?)?(client|secret|token|key)` is the shape
// a real credential assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)appd(ynamics)?[_\-]?(api[_\-]?)?(client|secret|token|key)`)

// minEntropy rejects low-information UUID-shaped runs (e.g. all-zero or
// repeated-nibble placeholders) that clear the hex layout but are not random
// secrets. UUID hex caps near 3.6 bits/char, so 3.0 is the conservative floor
// (3.5 would over-cull genuine UUIDs).
const minEntropy = 3.0

// armRe consumes the "appdynamics"/"appd" substrings the engine prefilters on,
// so contextKeywords is no longer needed. The bare keyword stays in Keywords()
// below as the chunk prefilter.

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AppDynamics }

func (Scanner) Keywords() []string { return []string{"appdynamics"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	clientHits := clientRe.FindAllSubmatchIndex(data, -1)
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(clientHits) == 0 || len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var client, secret string
	for _, h := range clientHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		client = string(data[h[2]:h[3]])
		break
	}
	if client == "" {
		return nil, nil
	}
	for _, h := range secretHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		// Skip the local-part of the client (regex would match it
		// because it overlaps secretRe shape). Compare excluding the
		// `@<account>` suffix.
		if idx := strings.Index(client, "@"); idx >= 0 && client[:idx] == v {
			continue
		}
		if v == client {
			continue
		}
		// Entropy gate: UUID-shaped runs that are structured placeholders
		// (all zeros, repeated nibbles) clear secretRe but are not real
		// secrets — reject them even when armed.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		secret = v
		break
	}
	if secret == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.AppDynamics,
		Raw:          []byte(client),
		RawV2:        []byte(secret),
		Redacted:     redact(client),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, client+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether an
// `appd(ynamics)?[_-]?(api[_-]?)?(client|secret|token|key)` reference appears
// within a tight window on either side of the candidate. The window spans both
// directions so a credential defined alongside a nearby APPDYNAMICS_SECRET
// reference still arms.
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
	user, pass := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&client_id=" + user + "&client_secret=" + pass)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/controller/api/oauth/access_token", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
