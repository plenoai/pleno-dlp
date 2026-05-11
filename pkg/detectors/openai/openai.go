// Package openai detects OpenAI API keys (sk-…, sk-proj-…, sk-svcacct-…,
// sk-admin-…) and verifies them against /v1/models. On a verified hit the
// detector also enriches ExtraData with the org id and the visible model
// inventory — driftwood pattern: a key that "works" should also tell you
// *what it works on*. Anthropic keys (sk-ant-…) share the "sk-" prefix and
// must be excluded — that responsibility lives in the regex filter below.
package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.openai.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Excludes sk-ant- via a negative-lookahead-equivalent: we match `sk-` then
// either `proj-` or any non-`a` char (or `a` not followed by `nt-`). Since Go
// regexp lacks lookaheads, we match broadly and filter in code.
var keyRe = regexp.MustCompile(`\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})\b`)

// notable models we surface so a triager can immediately see whether a key
// unlocks the expensive / sensitive surface.
var notableModels = []string{
	"gpt-4", "gpt-4o", "gpt-4-turbo", "o1", "o3", "dall-e-3", "whisper",
	"text-embedding-3-large", "tts-1",
}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.OpenAI }

// "sk-" alone would also catch Anthropic keys, but the engine's keyword filter
// is tolerant; the FromData regex + filter step does the discrimination.
func (Scanner) Keywords() []string { return []string{"sk-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	matches := keyRe.FindAll(data, -1)
	if len(matches) == 0 {
		return nil, nil
	}

	out := make([]detectors.Result, 0, len(matches))
	for _, m := range matches {
		token := string(m)
		// Hard exclude Anthropic — same prefix, different provider.
		if strings.HasPrefix(token, "sk-ant-") {
			continue
		}
		extra := map[string]string{
			"openai_key_kind": keyKind(token),
		}
		if isPrivilegedKind(extra["openai_key_kind"]) {
			extra["openai_privileged"] = "true"
		}
		res := detectors.Result{
			DetectorType: detectors.OpenAI,
			Raw:          []byte(token),
			Redacted:     redact(token),
			ExtraData:    extra,
		}
		if verify {
			v, meta, err := s.verifyWithMetadata(ctx, token)
			res.Verified = v
			res.VerificationErr = err
			for k, val := range meta {
				extra[k] = val
			}
		}
		out = append(out, res)
	}
	return out, nil
}

func (s Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	v, _, err := s.verifyWithMetadata(ctx, secret)
	return v, err
}

func (Scanner) verifyWithMetadata(ctx context.Context, secret string) (bool, map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiBase+"/v1/models", nil)
	if err != nil {
		return false, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return false, nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return false, nil, nil
	}

	meta := map[string]string{}
	if org := resp.Header.Get("openai-organization"); org != "" {
		meta["openai_organization"] = org
	}

	var body struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err == nil {
		meta["openai_models_count"] = strconv.Itoa(len(body.Data))
		if hits := matchNotableModels(body.Data); len(hits) > 0 {
			meta["openai_notable_models"] = strings.Join(hits, ",")
		}
	}
	return true, meta, nil
}

func matchNotableModels(data []struct {
	ID      string `json:"id"`
	OwnedBy string `json:"owned_by"`
}) []string {
	have := make(map[string]struct{}, len(data))
	for _, m := range data {
		have[m.ID] = struct{}{}
	}
	var out []string
	for _, want := range notableModels {
		// notable matches by exact id OR id-prefix (gpt-4 covers gpt-4-0613).
		for id := range have {
			if id == want || strings.HasPrefix(id, want+"-") || strings.HasPrefix(id, want) {
				out = append(out, want)
				break
			}
		}
	}
	return out
}

// keyKind tags the prefix family. Stripe pattern — every finding gets the
// kind regardless of verify success, so triagers can sort even on offline
// scans.
func keyKind(token string) string {
	switch {
	case strings.HasPrefix(token, "sk-proj-"):
		return "project"
	case strings.HasPrefix(token, "sk-svcacct-"):
		return "service-account"
	case strings.HasPrefix(token, "sk-admin-"):
		return "admin"
	case strings.HasPrefix(token, "sk-"):
		return "legacy-user"
	default:
		return "unknown"
	}
}

// isPrivilegedKind: legacy-user keys are user-scoped (full org access via
// the user's roles); admin keys are org-management-scoped. Both are
// "privileged" relative to project/service-account keys, which are scoped
// to a single project.
func isPrivilegedKind(k string) bool {
	return k == "legacy-user" || k == "admin"
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
