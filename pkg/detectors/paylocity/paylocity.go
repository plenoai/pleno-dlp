// Package paylocity detects Paylocity OAuth client_id + client_secret pairs
// near the `paylocity` keyword. Verified via /IdentityServer/connect/token on
// the gateway host (apigateway.paylocity.com production / sandbox host
// otherwise) — the per-account host isn't reliably in the chunk so verify
// requires apiBase override and ships unverified-by-default. Raw carries the
// client_id, RawV2 carries the client_secret.
package paylocity

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

// credRe matches the client_id / client_secret shape. Paylocity's auth docs
// show a 32-char lowercase-hex client_id (example dfff6fdfb9a145d59389542285dfa505)
// but do NOT document the client_secret length or charset, so we keep the
// permissive [A-Za-z0-9]{32,64} charset/length rather than pin to hex-32 and
// silently drop the undocumented secret half. The false-positive load is
// instead carried by the assignment-anchor arm regex + entropy floor below.
var credRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Paylocity reference that must appear within the
// proximity window. A bare "paylocity" substring (dependency names, doc URLs,
// comments) is too weak; a `paylocity[_-]?(client[_-]?)?(id|secret|key|token)`
// reference is the shape a real credential assignment / config key takes.
var armRe = regexp.MustCompile(`(?i)paylocity[_\-]?(client[_\-]?)?(id|secret|key|token)`)

// minEntropy rejects low-variety 32-64 char runs that clear the alnum regex but
// are not random credentials. Held at 3.0 (not 3.5): the documented hex
// client_id example dfff6fdfb9a145d59389542285dfa505 measures ~3.38, so a 3.5
// floor would silently cull legitimate Paylocity client_ids. 3.0 keeps hex
// recall while still rejecting padded/structured identifiers.
const minEntropy = 3.0

// "paylocity" stays in Keywords() as the cheap engine-level prefilter; the
// arm regex above is the precise gate applied after the prefilter fires.

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Paylocity }

func (Scanner) Keywords() []string { return []string{"paylocity"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := credRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	type cand struct {
		val string
	}
	creds := make([]cand, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		// Entropy gate: reject low-variety 32-64 char runs (padded names,
		// structured identifiers) that clear the alnum regex but are not
		// random credentials. Applied to both halves of the id+secret pair.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, cand{val: v})
	}
	if len(creds) < 2 {
		return nil, nil
	}
	clientID, clientSecret := creds[0].val, creds[1].val
	res := detectors.Result{
		DetectorType: detectors.Paylocity,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientSecret),
		Redacted:     redact(clientID),
	}
	if verify && apiBase != "" {
		v, err := s.Verify(ctx, clientID+":"+clientSecret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether an assignment-style Paylocity credential
// reference (armRe) appears within a tight window on either side of the
// candidate. The window spans both directions (not strict immediate
// precedence) so an id/secret defined alongside a nearby PAYLOCITY_CLIENT_ID
// reference still arms. Radius is 64 (tightened from 256) — a bare "paylocity"
// substring over a wide window let unrelated 32-64 char tokens through.
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
	body := strings.NewReader("grant_type=client_credentials&scope=WebLinkAPI")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/IdentityServer/connect/token", body)
	if err != nil {
		return false, err
	}
	req.SetBasicAuth(id, sec)
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
