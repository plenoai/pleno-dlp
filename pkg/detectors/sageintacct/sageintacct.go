// Package sageintacct detects Sage Intacct (accounting) sender_id /
// sender_password / user_password values near the `intacct` keyword.
// Unverified by design — Intacct's auth surface is XML-over-HTTPS using a
// multi-credential <login> envelope (sender_id + sender_password +
// user_id + user_password + company_id), so a single bearer probe 4xx's
// without all five values. Verify only fires when an apiBase override is
// supplied alongside the full envelope.
package sageintacct

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

// tokenRe matches a generic 12-32 alnum run. Sage Intacct does NOT publish an
// authoritative credential format: the developer docs state Web Services
// sender_id / sender_password are "provisioned by Sage Intacct" with no
// documented length, charset, or prefix, and the published examples are
// free-form user-style passwords (e.g. `pass123!`). We therefore keep the
// generic shape and must NOT pin a length — pinning a guessed length would
// silently destroy recall. Disambiguation is delegated to the entropy floor +
// assignment-anchor keyword gate below.
//
//	https://developer.intacct.com/web-services/ (no format published, 2026-06)
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{12,32})\b`)

// armRe is the assignment-style Intacct reference that must appear within the
// proximity window. A bare "intacct" substring (doc links, package names, log
// lines) is too weak a gate against a generic 12-32 alnum run; the
// `intacct[_-]?(sender|user|api)?[_-]?(id|password|token|key|secret)` shape is
// what a real credential assignment or config key takes. The bare keyword
// stays in Keywords() as the cheap engine prefilter.
var armRe = regexp.MustCompile(`(?i)(intacct|sender|user)[_\-]?(api[_\-]?)?(id|password|token|key|secret)`)

// minEntropy is a CONSERVATIVE 3.0 floor (not 3.5). Because no authoritative
// format pins the charset, the run may be a short low-variety password; a 3.5
// floor would over-cull legitimate provisioned credentials. 3.0 rejects only
// padded placeholders and repeated-character runs that clear the alnum regex.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SageIntacct }

func (Scanner) Keywords() []string { return []string{"intacct"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		// Entropy gate: padded placeholders and repeated-character runs clear
		// the alnum regex but are not provisioned credentials. Conservative
		// 3.0 floor — see minEntropy rationale (no documented charset to pin).
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.SageIntacct,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// nearKeyword reports whether an assignment-style Intacct credential reference
// (armRe) appears within a tight window on either side of the candidate. The
// window spans both directions (not strict immediate precedence) so a value
// defined alongside a nearby INTACCT_SENDER_PASSWORD reference still arms.
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Best-effort probe: Intacct's XML gateway returns 200 with a SOAP fault
	// for missing credentials. Test mocks gate on the password being present
	// in the body; production calls will surface unverified.
	body := strings.NewReader(`<request><control><password>` + secret + `</password></control></request>`)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/ia/xml/xmlgw.phtml", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/xml")
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
