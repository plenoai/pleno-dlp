// Package supabase detects Supabase service-role keys (JWT with
// `role:"service_role"` near a `supabase` keyword).
//
// Verify is intentionally not performed. The service-role key is bound
// to a per-project URL (`https://<ref>.supabase.co`) — that ref isn't
// always co-located in source, and probing the wrong project would
// either 401 (false negative) or hit an unrelated tenant. We surface
// unverified-by-design at SeverityCritical when the role claim says
// service_role and parse the project ref into ExtraData["project_ref"]
// when it appears in the same chunk.
package supabase

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// JWT shape — same prefix gate as the generic JWT detector. The
// supabase-specific filter is the `role` claim plus the keyword.
var jwtRe = regexp.MustCompile(`\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,})\b`)

// Project URL ref capture: https://<ref>.supabase.co.
var projectRe = regexp.MustCompile(`\bhttps?://([a-z0-9-]{20})\.supabase\.co\b`)

var contextKeywords = []string{"supabase", "supabase_url", "supabase_anon", "supabase_service_role", "service_role"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Supabase }

func (Scanner) Keywords() []string { return []string{"supabase", "service_role"} }

func (s Scanner) FromData(_ context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	matches := jwtRe.FindAllSubmatchIndex(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))

	// Project ref is shared across all keys in the chunk.
	projectRef := ""
	if pm := projectRe.FindStringSubmatch(string(data)); len(pm) == 2 {
		projectRef = pm[1]
	}

	out := make([]detectors.Result, 0, len(matches))
	seen := map[string]struct{}{}
	for _, m := range matches {
		token := string(data[m[2]:m[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, m[2], m[3]) {
			continue
		}
		role, ref := parseClaims(token)
		// Only claim Supabase JWTs — payload must carry a Supabase-shaped
		// `role` claim. This keeps us out of the generic JWT detector's
		// keyspace.
		if role == "" {
			continue
		}
		seen[token] = struct{}{}
		extra := map[string]string{"role": role}
		if ref != "" {
			extra["jwt_project_ref"] = ref
		}
		if projectRef != "" {
			extra["project_ref"] = projectRef
		}
		// Service-role keys are admin-equivalent — surface Critical even
		// without verification. anon keys still leak project identity but
		// expose no row-level admin path; surface High via package default.
		sev := detectors.SeverityHigh
		if role == "service_role" {
			sev = detectors.SeverityCritical
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.Supabase,
			Raw:          []byte(token),
			Redacted:     redact(token),
			Severity:     sev,
			ExtraData:    extra,
		})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// parseClaims extracts (role, ref) from the JWT payload. ref is the
// `ref` claim that supabase embeds for hosted projects. Both default
// to "" on parse failure.
func parseClaims(token string) (string, string) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", ""
	}
	pl, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var p struct {
		Role string `json:"role"`
		Ref  string `json:"ref"`
	}
	if err := json.Unmarshal(pl, &p); err != nil {
		return "", ""
	}
	return p.Role, p.Ref
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
