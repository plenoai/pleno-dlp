// Package databricks detects Databricks personal access tokens (`dapi`
// followed by 32 lowercase hex chars).
//
// Verify is intentionally not performed inline. The Databricks API endpoint
// host is workspace-scoped (`<workspace>.cloud.databricks.com` or an Azure /
// AWS region equivalent) and is rarely embedded next to the token in source.
// Probing a guessed host risks both wrong-account audit-log entries and false
// negatives. So databricks surfaces unverified-by-design and the engine
// renders it under --unverified-results.
//
// When a workspace host *is* present in the chunk we capture it in
// ExtraData["host"] so reviewers can probe manually. The token itself grants
// the issuing user's full configured scope, so unverified hits ship at
// SeverityHigh per the package default.
package databricks

import (
	"context"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// `dapi` + 32 lowercase hex. Older PATs exist as 32 hex without the `dapi`
// prefix but those collide with md5/sha1 shapes; we reject them and only
// surface the unambiguous prefixed variant.
var tokenRe = regexp.MustCompile(`\b(dapi[a-f0-9]{32})\b`)

// Optional workspace host capture for ExtraData.
var hostRe = regexp.MustCompile(`\b([a-z0-9-]+\.cloud\.databricks\.com|adb-[0-9]+\.[0-9]+\.azuredatabricks\.net)\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Databricks }

// `dapi` is distinctive and short enough that prefiltering is cheap.
func (Scanner) Keywords() []string { return []string{"dapi"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
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
		out = append(out, res)
	}
	return out, nil
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
