// Package smee detects smee.io webhook proxy channel URLs — the URL
// itself is the credential. Unverified by design — there is no
// authentication probe; an HTTP probe to the channel posts a real
// event, which we will not do.
package smee

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var tokenRe = regexp.MustCompile(`https?://smee\.io/([A-Za-z0-9]{8,})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Smee }

func (Scanner) Keywords() []string { return []string{"smee.io"} }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatch(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(h[0])
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Smee,
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
