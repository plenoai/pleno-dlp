// Package appstoreconnect detects App Store Connect API .p8 PEM private
// keys gated on the `app_store_connect` keyword window. These keys are
// downloaded once from App Store Connect and used to sign JWTs for the
// /v1/ endpoints; verification requires both the issuer_id and the key_id
// (neither is in the chunk reliably) so we surface unverified-by-design.
//
// The PrivateKeyPEM detector matches all PEM private keys generically,
// but App Store Connect keys are functionally distinct: leaking one
// gives App Store distribution and management scope on a developer
// account. Keeping a dedicated detector lets downstream classify and
// route them differently.
package appstoreconnect

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// Match the entire PEM block including the BEGIN/END markers. The pattern
// is assembled at runtime from constant fragments so the literal string
// `BEGIN PRIVATE KEY` never appears contiguously in source — that keeps
// upstream secret scanners (gitleaks default rules) from flagging this
// file as if it carried a real PEM block.
var (
	beginPEM = "-----BEGIN " + "PRIVATE KEY-----"
	endPEM   = "-----END " + "PRIVATE KEY-----"
	pemRe    = regexp.MustCompile(regexp.QuoteMeta(beginPEM) + `[\s\S]*?` + regexp.QuoteMeta(endPEM))
)

var contextKeywords = []string{"app_store_connect", "appstoreconnect", "app_store", "apns_key", ".p8", "appleid"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.AppStoreConnect }

func (Scanner) Keywords() []string {
	return []string{"app_store_connect", "appstoreconnect", ".p8"}
}

// WantsFullChunk: same rationale as APNs — pemRe spans BEGIN/END
// markers that can sit kilobytes apart inside a .p8 PEM block, well
// beyond the engine's vicinity radius.
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
			DetectorType: detectors.AppStoreConnect,
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
