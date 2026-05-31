// Package marketo detects Marketo REST API client_id + client_secret pairs
// near the `marketo` keyword. Verified via /identity/oauth/token on the
// per-tenant host (`<munchkin>.mktorest.com`). Unverified-by-default —
// the munchkin host isn't in the chunk; verify only fires when an apiBase
// override is supplied. Raw carries the client_id, RawV2 the secret.
//
// FP hardening: Marketo is a two-part credential. The client_id is a UUID v4
// (e.g. <UUID-V4-CLIENT-ID>) per Adobe/Marketo's official auth docs and the
// provider-owned REST-Sample-Code; the client_secret is a 32-char alphanumeric
// value per the same sample code. The old detector matched BOTH halves with a
// bare `[A-Za-z0-9]{24,64}` behind a radius-256 `strings.Contains(..,"marketo")`
// gate and no entropy floor — random alnum runs near the word "marketo" matched
// trivially. We now anchor the id on its UUID shape (a strong structural
// anchor), pin the secret to the documented 32-char length with a Shannon
// entropy floor, and replace the bare keyword scan with an assignment-anchor
// arm regex inside a tight 64-byte window.
package marketo

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

// idRe matches the Marketo client_id, a UUID v4. This is the authoritative
// distinguishing shape (Adobe/Marketo docs + provider sample code) and acts as
// the structural anchor for the id half — a generic alnum run can no longer
// masquerade as the client_id.
var idRe = regexp.MustCompile(`\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`)

// secretRe matches the client_secret, a 32-char alphanumeric value per the
// provider's REST-Sample-Code. No public prefix exists, so the length pin plus
// the entropy floor and the arm-regex window carry the false-positive load.
var secretRe = regexp.MustCompile(`\b([A-Za-z0-9]{32})\b`)

// minEntropy rejects low-information 32-char runs (padded identifiers, repeated
// patterns) that clear secretRe but lack secret-grade randomness. 3.5 suits a
// high-variety base62 charset (hex caps ~3.6, base62 sits well above).
const minEntropy = 3.5

// armRe is the assignment-style Marketo reference that must appear within the
// proximity window. A bare "marketo" substring (docs, URLs, package names) is
// too weak; the `marketo[_-]?(client_)?(id|secret|key|token)` /
// `mktorest`-style forms are what a real credential assignment or config key
// takes.
var armRe = regexp.MustCompile(`(?i)(marketo|mktorest)[_\-]?(client[_\-]?)?(id|secret|key|token)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Marketo }

// Keywords must include the bare provider words so the engine prefilter arms
// the chunk; the tighter armRe disambiguates inside FromData.
func (Scanner) Keywords() []string { return []string{"marketo", "mktorest"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	idHits := idRe.FindAllSubmatchIndex(data, -1)
	if len(idHits) == 0 {
		return nil, nil
	}
	secretHits := secretRe.FindAllSubmatchIndex(data, -1)
	if len(secretHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	id := firstArmed(data, lower, idHits, false)
	if id == "" {
		return nil, nil
	}
	secret := firstArmed(data, lower, secretHits, true)
	if secret == "" {
		return nil, nil
	}

	res := detectors.Result{
		DetectorType: detectors.Marketo,
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

// firstArmed returns the first regex hit that is armed by a nearby Marketo
// assignment reference. When entropyGate is set the candidate must also clear
// the Shannon entropy floor (used for the secret half; the UUID id is already
// structurally constrained).
func firstArmed(data []byte, lower string, hits [][]int, entropyGate bool) string {
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if entropyGate && !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		return v
	}
	return ""
}

// nearKeyword reports whether an armRe reference appears within a tight 64-byte
// window on either side of the candidate. The window spans both directions so a
// credential defined alongside a nearby MARKETO_CLIENT_ID reference still arms.
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
	url := strings.TrimRight(apiBase, "/") + "/identity/oauth/token?grant_type=client_credentials&client_id=" + id + "&client_secret=" + sec
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false, err
	}
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
