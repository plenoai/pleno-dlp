// Package apns detects Apple Push Notification service .p8 PEM private keys
// gated on the `apns` keyword window. APNs auth keys are downloaded once
// from the Apple developer portal and are used to sign JWTs targeting
// api.push.apple.com. Verification requires both the issuer (team_id) and
// key_id (neither is in the chunk reliably) so we surface unverified-by-
// design.
//
// Distinct from the AppStoreConnect detector: APNs keys grant push-send
// scope on a bundle ID, App Store Connect keys grant store/distribution
// management. Distinct from the generic PrivateKeyPEM detector because
// the keyword gating routes them to a push-specific severity downstream.
package apns

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// PEM markers assembled at runtime so the literal `BEGIN PRIVATE KEY`
// never appears contiguously in source.
var (
	beginPEM = "-----BEGIN " + "PRIVATE KEY-----"
	endPEM   = "-----END " + "PRIVATE KEY-----"
	pemRe    = regexp.MustCompile(regexp.QuoteMeta(beginPEM) + `[\s\S]*?` + regexp.QuoteMeta(endPEM))
)

var contextKeywords = []string{"apns", "apns_auth_key", "apns_key_id", "apple_push", "push.apple.com"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.APNs }

func (Scanner) Keywords() []string {
	return []string{"apns", "apple_push"}
}

// WantsFullChunk: pemRe pairs BEGIN/END markers that can sit several
// kilobytes apart inside a PEM block. The engine's vicinity dispatch
// would split the pair into separate slices on a real .p8 file.
func (Scanner) WantsFullChunk() bool { return true }

func (Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	hits := pemRe.FindAllIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		pem := string(data[h[0]:h[1]])
		if _, dup := seen[pem]; dup {
			continue
		}
		if !nearKeyword(lower, h[0], h[1]) {
			continue
		}
		seen[pem] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.APNs,
			Raw:          []byte(pem),
			Redacted:     beginPEM + "...",
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
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

func init() {
	detectors.Register(Scanner{})
}
