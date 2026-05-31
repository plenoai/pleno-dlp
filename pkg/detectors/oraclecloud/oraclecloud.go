// Package oraclecloud detects Oracle Cloud Infrastructure (OCI) auth tokens —
// long alphanumerics near an assignment-style OCI reference. OCI uses
// signed-request authentication; verify requires per-tenancy host
// (`<region>.oraclecloud.com`) and is unverified-by-default. Verify only
// fires when an apiBase override is supplied.
//
// Oracle does not publicly document the Auth Token length or charset (the
// console only shows an obfuscated example such as <TOKEN>), and there is no
// upstream trufflehog oraclecloud detector to mirror. We therefore do NOT pin
// a token length and apply only recall-safe gate-tightening: a tight (radius
// 64) assignment-anchor arm regex replaces the prior bare-substring/radius-256
// gate, and a conservative HasMinEntropy(token, 3.0) floor culls structured
// runs without guessing the real-token alphabet.
package oraclecloud

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

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

// minEntropy is a CONSERVATIVE floor. Oracle does not publicly document the
// OCI Auth Token length or charset (only an obfuscated console example), so we
// deliberately avoid the 3.5 floor used for documented base62 keys — 3.0 culls
// padded/structured 32+ char runs without risking recall against an unknown
// real-token alphabet.
const minEntropy = 3.0

// armRe is the assignment-style OCI reference that must appear within the
// proximity window. A bare "oraclecloud"/"oci_" substring over a wide radius
// (dependency names, region hostnames, dotted OCIDs in unrelated config) is too
// weak. We require an `oci`/`oraclecloud` stem joined by separators to a
// token/key/secret/auth noun (allowing one intermediate identifier segment such
// as the real-world `OCI_TENANCY_KEY` / `oci_auth_token` shapes). The `ocid1.`
// OCID prefix is also accepted directly as a strongly distinctive OCI marker.
// Keywords() keeps the bare stems as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)(oci|oraclecloud)[_\-]?(\w+[_\-])?(auth|api)?[_\-]?(token|key|secret)|ocid1\.`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OracleCloud }

func (Scanner) Keywords() []string { return []string{"oraclecloud", "ocid1.", "oci_"} }

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
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Conservative entropy gate: 32+ char alphanumerics are a generic shape
		// (hashes, padded identifiers, base32 blobs). 3.0 rejects low-information
		// runs while staying recall-safe against an undocumented real-token charset.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.OracleCloud,
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

// nearKeyword reports whether an assignment-style OCI reference appears within
// a tight window on either side of the candidate. Tightened from radius 256 +
// bare strings.Contains to radius 64 + an arm regex: a bare "oci_"/"oraclecloud"
// substring over a wide window armed on unrelated config and hostnames.
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/20160918/users/me", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Signature "+secret)
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
