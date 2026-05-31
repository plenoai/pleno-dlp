// Package databricks detects Databricks personal access tokens (`dapi`
// followed by 32 lowercase hex chars).
//
// The token IS the credential the Databricks REST API accepts directly as a
// bearer token (`Authorization: Bearer <dapi-token>`), so no RawV2 pairing is
// required. Verification is performed against the workspace REST API:
//
//	GET <host>/api/2.0/clusters/list
//	Authorization: Bearer <token>
//	200       -> Verified=true
//	401 / 403 -> Verified=false (explicit rejection)
//	429       -> unverified, no retry (transient)
//	5xx       -> unverified, no retry (transient)
//
// The endpoint host is workspace-scoped (`<workspace>.cloud.databricks.com` or
// an Azure `adb-N.N.azuredatabricks.net` equivalent) and is NOT derivable from
// the token itself. The host is therefore sourced two ways:
//
//   - operator override via the package-level `apiBase` (the canonical path the
//     engine wires up), or
//   - a best-effort host captured from the same chunk into ExtraData["host"],
//     which can seed a derived host when no override is configured.
//
// When neither a host override nor a chunk-local host is available, Verify
// no-ops (returns false, nil) rather than probing a guessed host — guessing
// risks wrong-account audit-log entries and false negatives. Per repo policy a
// Verify that no-ops without a host still counts as class (a); this matches the
// established Front/Heap/Chargebee pattern. `/api/2.0/clusters/list` is an
// authenticated read with no anonymous-200 path, and because the host is
// operator-supplied or chunk-derived, a wrong host returns non-200, so there is
// no false Verified=true risk.
package databricks

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// apiBase, when non-empty, overrides the workspace host for verification. It is
// left empty by default so production verify no-ops unless an operator wires a
// workspace host (or a chunk-local host is derived). Tests override it with an
// httptest.Server URL.
var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

var (
	verifyAcceptCodes = []int{http.StatusOK}
	verifyRejectCodes = []int{http.StatusUnauthorized, http.StatusForbidden}
)

// `dapi` + 32 lowercase hex. Older PATs exist as 32 hex without the `dapi`
// prefix but those collide with md5/sha1 shapes; we reject them and only
// surface the unambiguous prefixed variant.
var tokenRe = regexp.MustCompile(`\b(dapi[a-f0-9]{32})\b`)

// Optional workspace host capture for ExtraData / host derivation.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.cloud\.databricks\.com|adb-[0-9]+\.[0-9]+\.azuredatabricks\.net)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Databricks }

// `dapi` is distinctive and short enough that prefiltering is cheap.
func (Scanner) Keywords() []string { return []string{"dapi"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := tokenRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	host := hostRe.FindString(string(data))
	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(m)
		if _, dup := seen[token]; dup {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{}
		if host != "" {
			extra["host"] = strings.ToLower(host)
		}
		res := detectors.Result{
			DetectorType: detectors.Databricks,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			// Prefer an operator-configured host override; otherwise seed from
			// the chunk-local host. resolveHost no-ops when neither is present.
			v, err := verifyToken(ctx, token, extra["host"])
			res.Verified = v
			res.VerificationErr = err
		}
		out = append(out, res)
	}
	return out, nil
}

// Verify satisfies the Verifier interface. The host is taken from the apiBase
// override; without it Verify no-ops (see package doc). The engine-level verify
// path uses this entry point.
func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	return verifyToken(ctx, secret, "")
}

// resolveHost returns the base URL to probe. The apiBase override wins; when it
// is empty a chunk-derived host (bare workspace domain) is promoted to https.
// Returns "" when no host is available, signalling the caller to no-op.
func resolveHost(chunkHost string) string {
	if apiBase != "" {
		return strings.TrimRight(apiBase, "/")
	}
	if chunkHost != "" {
		return "https://" + strings.TrimRight(chunkHost, "/")
	}
	return ""
}

func verifyToken(ctx context.Context, token, chunkHost string) (bool, error) {
	base := resolveHost(chunkHost)
	if base == "" {
		// No host to probe — no-op rather than guess.
		return false, nil
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/2.0/clusters/list", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, doErr := httpClient.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	return detectors.ClassifyVerifyHTTP(resp, doErr, verifyAcceptCodes, verifyRejectCodes)
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
