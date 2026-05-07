// Package vault detects HashiCorp Vault tokens (`hvs.…`, `hvb.…`, legacy
// `s.…` service tokens).
//
// Verify is intentionally not implemented. Vault is self-hosted; the server
// URL (`VAULT_ADDR`) varies per deployment and is rarely embedded next to the
// token in source. Probing a wrong URL is not just useless, it's a covert
// scan against unrelated infrastructure — so we surface unverified.
package vault

import (
	"context"
	"regexp"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var (
	// Modern wrapped service / batch tokens: `hvs.<base64url>` and
	// `hvb.<base64url>`. Length floor is generous; Vault mints both ~95
	// chars for service tokens, ~60 for batch.
	modernRe = regexp.MustCompile(`\b(hv[sb]\.[A-Za-z0-9_-]{40,})\b`)
	// Legacy service tokens: `s.<24 base62 chars>`. The 24-char floor is
	// the documented length; we anchor the leading `s.` and a word boundary
	// to avoid matching `s.something` in Go pkg paths.
	legacyRe = regexp.MustCompile(`\bs\.([A-Za-z0-9]{24})\b`)
)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Vault }

// hvs./hvb. prefixes are extremely distinctive. The legacy s. prefix is too
// short to prefilter on alone, so we add the keyword "vault" so chunks that
// reference Vault still flow through even if only legacy tokens are present.
func (Scanner) Keywords() []string { return []string{"hvs.", "hvb.", "vault"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	for _, m := range modernRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Vault,
			Raw:          []byte(token),
			Redacted:     redact(token),
		})
	}
	for _, m := range legacyRe.FindAll(data, -1) {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		out = append(out, detectors.Result{
			DetectorType: detectors.Vault,
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
	if len(t) <= 6 {
		return t
	}
	return t[:6] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
