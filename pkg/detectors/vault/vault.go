// Package vault detects HashiCorp Vault tokens (`hvs.…`, `hvb.…`, legacy
// `s.…` service tokens).
//
// Verification: the matched token IS itself a Vault auth token, so the
// canonical self-introspection endpoint GET /v1/auth/token/lookup-self
// authenticates exactly that token via the X-Vault-Token header (mirroring
// trufflehog's HashiCorp Vault convention). Vault is self-hosted: VAULT_ADDR
// varies per deployment and is essentially never embedded next to the token
// in source. We therefore default apiBase to empty and no-op Verify (returns
// false, nil) unless an operator supplies a host override. This preserves the
// original safety concern — never covertly probe unrelated infrastructure —
// while a wrong/operator-supplied host yields a connection error or 403, never
// a false Verified=true.
package vault

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase is the Vault server address (VAULT_ADDR). It is empty by default:
// Vault is self-hosted and the host is absent from the scanned chunk, so we
// never probe a guessed endpoint. Operators (and tests) override this to opt
// into live verification against a known instance.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

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

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	out := []detectors.Result{}
	seen := map[string]struct{}{}

	add := func(token string) {
		if _, dup := seen[token]; dup {
			return
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Vault,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify {
			v, err := s.Verify(ctx, token)
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}

	for _, m := range modernRe.FindAll(data, -1) {
		add(string(m))
	}
	for _, m := range legacyRe.FindAll(data, -1) {
		add(string(m))
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// Verify introspects the token against its own Vault instance via
// GET /v1/auth/token/lookup-self with the token carried in the X-Vault-Token
// header (not Bearer). Without an apiBase override the host is unknown, so we
// no-op (false, nil) rather than probe unrelated infrastructure.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	base := strings.TrimRight(apiBase, "/")
	if base == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Vault-Token", secret)
	resp, err := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	// 200 -> valid; 401/403/404 -> invalid; 429/5xx -> transient (error).
	return detectors.ClassifyVerifyHTTP(resp, err, []int{200}, []int{401, 403, 404, 429})
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
