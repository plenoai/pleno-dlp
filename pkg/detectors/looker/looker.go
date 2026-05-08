// Package looker detects Looker API3 client_id + client_secret pairs
// near the `looker` keyword. Paired credential — Raw=client_id,
// RawV2=client_id+":"+client_secret. Unverified by default because
// verification requires the customer's per-tenant Looker host
// (xxx.looker.com or xxx.cloud.looker.com); the keys themselves don't
// encode the host.
package looker

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{20})\b`)

var contextKeywords = []string{"looker"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Looker }

func (Scanner) Keywords() []string { return []string{"looker"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var clientID, clientSecret string
	for _, h := range hits {
		v := string(data[h[2]:h[3]])
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		if clientID == "" {
			clientID = v
			continue
		}
		if v == clientID {
			continue
		}
		clientSecret = v
		break
	}
	if clientID == "" || clientSecret == "" {
		return nil, nil
	}
	return []detectors.Result{{
		DetectorType: detectors.Looker,
		Raw:          []byte(clientID),
		RawV2:        []byte(clientID + ":" + clientSecret),
		Redacted:     redact(clientID),
	}}, nil
}

func nearKeyword(lower string, start, end int) bool {
	const radius = 256
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	window := lower[from:to]
	for _, kw := range contextKeywords {
		if strings.Contains(window, kw) {
			return true
		}
	}
	return false
}

func redact(t string) string {
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
