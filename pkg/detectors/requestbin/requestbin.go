// Package requestbin detects RequestBin / Pipedream webhook URLs —
// `https://*.m.pipedream.net/<id>` or `https://*.requestbin.com/<id>`.
// The URL is the credential. Unverified by design — probing the URL
// posts a real event we will not generate.
package requestbin

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`https?://[A-Za-z0-9]+\.(?:m\.pipedream\.net|requestbin\.com|requestbin\.net)/[A-Za-z0-9]{8,}`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.RequestBin }

func (Scanner) Keywords() []string { return []string{"pipedream.net", "requestbin.com", "requestbin.net"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAll(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.RequestBin,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func redact(t string) string {
	if len(t) <= 24 {
		return t
	}
	return t[:24] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
