// Package pardot detects Salesforce Pardot / Account Engagement business
// unit id + access token pairs near the `pardot` keyword. Verified via
// /api/v5/objects/account on pi.pardot.com sending Bearer auth and the
// Pardot-Business-Unit-Id header. Raw carries the business unit id, RawV2
// the access token.
package pardot

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://pi.pardot.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// buRe matches the Account Engagement Business Unit ID. Salesforce documents
// this as a value that "begins with '0Uv' and is 18 characters long" — a
// Salesforce 18-char ID (15-char case-sensitive key + 3-char checksum suffix),
// charset [A-Za-z0-9]. The `0Uv` prefix is the distinguishing anchor, so this
// half needs no entropy gate.
// Source: developer.salesforce.com/docs/marketing/pardot/guide/authentication.html
var buRe = regexp.MustCompile(`\b(0Uv[A-Za-z0-9]{15})\b`)

// tokenRe matches the Salesforce OAuth access token used as the Bearer
// credential. A real Salesforce access token is shaped `00D<15-char-orgid>!`
// followed by a tail that includes `.`, `_` and other non-alnum separators
// (e.g. `00DB0000000TfcR!AQQAQFhoK8vTMg_rKA.esrJ2bCs...`), so the previous
// bare `[A-Za-z0-9]{18,256}` regex could not even match a genuine token — it
// only captured whatever generic alnum run sat near the keyword. We anchor on
// the documented `00D` org-id prefix and widen the tail charset to the real
// token alphabet so live tokens match.
// Source: Salesforce Help "OAuth Tokens" (remoteaccess_oauth_tokens) example
// token `00DB0000000TfcR!AQQA...`; Pardot auth uses a Salesforce OAuth token.
//
// Both forms anchor on the documented `00D` org-id prefix: the full
// `00D<orgid>!<tail>` shape (real live token), and a prefix-anchored alnum
// fallback for environments/fixtures that strip the `!`-separated session
// material. The `00D` anchor + entropy 3.5 replaces the previous unanchored
// `[A-Za-z0-9]{18,256}`.
var tokenRe = regexp.MustCompile(`\b(00D[A-Za-z0-9]{12,18}![A-Za-z0-9._\-]{20,}|00D[A-Za-z0-9]{15,253}\b)`)

// armRe is the assignment-style Pardot reference that must appear within the
// proximity window. A bare "pardot" substring (script-src URLs, doc links,
// tracker JS) is too weak a gate; `pardot[_-]?(business[_-]?unit[_-]?id|
// (api[_-]?)?(token|key|secret|bu))` is the shape a real credential
// assignment or config key takes.
var armRe = regexp.MustCompile(`(?i)pardot[_\-]?(business[_\-]?unit[_\-]?id|(api[_\-]?)?(token|key|secret|bu|id))`)

// minTokenEntropy rejects low-information runs that clear the token regex but
// lack key-grade randomness. The access-token charset is high-variety, so 3.5
// is safe.
const minTokenEntropy = 3.5

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Pardot }

func (Scanner) Keywords() []string { return []string{"pardot"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	buHits := buRe.FindAllSubmatchIndex(data, -1)
	tokHits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(buHits) == 0 || len(tokHits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	var id string
	for _, h := range buHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		id = string(data[h[2]:h[3]])
		break
	}
	if id == "" {
		return nil, nil
	}

	var secret string
	for _, h := range tokHits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == id {
			continue
		}
		// Entropy gate: structured/low-information runs that clear the token
		// regex (e.g. a padded placeholder) are not real OAuth tokens.
		if !detectors.HasMinEntropy(v, minTokenEntropy) {
			continue
		}
		secret = v
		break
	}
	if secret == "" {
		return nil, nil
	}

	res := detectors.Result{
		DetectorType: detectors.Pardot,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify {
		v, err := s.Verify(ctx, id+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether an assignment-style Pardot reference appears
// within a tight window on either side of the candidate. radius 256 -> 64.
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
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	bu, tok := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v5/objects/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Pardot-Business-Unit-Id", bu)
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
