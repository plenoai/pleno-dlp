// Package mandiant detects Mandiant Advantage API key + secret pairs
// near the `mandiant` / `fireeye` keyword. Verified via /token (OAuth
// client_credentials) on api.intelligence.fireeye.com using HTTP Basic
// auth (key as username, secret as password). Raw=key, RawV2=key:secret
// per the trufflehog convention for paired credentials.
package mandiant

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.intelligence.fireeye.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Mandiant API keys and secret IDs are alnum runs. We match each
// independently then pair them within the chunk if both appear near the
// keyword.
//
// NOTE on length: Mandiant's API docs are partner/customer-only and not
// public; neither the official google/mandiant-ti-client nor any public
// integration documents a prefix, length, or charset for the Key ID /
// Secret. So the {32,64} bound is NOT authoritatively pinned — it is left
// as-is to preserve recall. Disambiguation is done by the arm regex +
// entropy gate, not by length.
var keyRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,64})\b`)

// armRe is the assignment-style Mandiant reference that must appear within
// the proximity window. A bare "mandiant" / "fireeye" substring (doc links,
// vendor mentions, the api.intelligence.fireeye host) is too weak a gate
// against a generic 32-64 alphanumeric run; the
// `(mandiant|fireeye)[_-]?(api[_-]?)?(key|token|secret|id)` shape is what a
// real credential assignment or config key takes. The bare keywords stay in
// Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)(mandiant|fireeye)[_\-]?(api[_\-]?)?(key|token|secret|id)`)

// minEntropy rejects low-information 32-64 char runs (padded placeholders,
// repeated characters, structured IDs) that clear the alnum regex but are not
// random credentials. 3.0 is conservative: the credential format is
// undocumented, so a tighter floor would risk silently culling real keys.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Mandiant }

func (Scanner) Keywords() []string { return []string{"mandiant", "fireeye"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := keyRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	// Collect the first two keyword-adjacent unique tokens — Mandiant
	// distributes credentials as a pair (api_key + secret_id) and they
	// almost always appear in the same chunk near `mandiant`.
	var tokens []string
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Entropy gate: structured/low-information 32-64 char runs clear the
		// alnum regex but are not random credentials — reject them even when
		// armed. Applied to both halves of the pair.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		tokens = append(tokens, token)
		if len(tokens) == 2 {
			break
		}
	}
	if len(tokens) < 2 {
		return nil, nil
	}
	key, secret := tokens[0], tokens[1]
	res := detectors.Result{
		DetectorType: detectors.Mandiant,
		Raw:          []byte(key),
		RawV2:        []byte(key + ":" + secret),
		Redacted:     redact(key),
	}
	if verify {
		v, err := s.Verify(ctx, key+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether a
// `(mandiant|fireeye)[_-]?(api[_-]?)?(key|token|secret|id)` reference appears
// within a tight window on either side of the candidate. The window spans both
// directions (not strict immediate precedence) so a key defined alongside a
// nearby MANDIANT_API_KEY / MANDIANT_SECRET reference still arms.
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

// Verify expects secret formatted as "key:secret".
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	key, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&scope=appliance.collector")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/token", body)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(key + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
