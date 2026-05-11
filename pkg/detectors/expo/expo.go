// Package expo detects Expo personal access tokens used by the Expo
// CLI and Expo Application Services (EAS). Tokens are 32-character
// [A-Za-z0-9_-] strings without a fixed self-identifying prefix, so
// they are easily confused with git SHAs (40 hex chars), JWT
// segments, base64 hashes, npm sha512 fragments, and other opaque
// alphanumeric blobs. To keep noise low we require an explicit
// Expo-shaped keyword (EXPO_TOKEN / EXPO_ACCESS_TOKEN / expo.dev /
// eas.dev / "expo " bordered) within a small window of the candidate.
//
// Importantly we never trigger on the bare substring "expo": the
// previous implementation called strings.Contains(window, "expo")
// which matched export, exposure, exposed, exponent, exposing and
// every other English word containing the letters e-x-p-o. The new
// keyword regex anchors on explicit separators (`_`, `.`, `:`, `=`,
// whitespace, end-of-string) so those words no longer qualify.
//
// Verified via /v2/auth/userInfo on exp.host with Authorization
// Bearer header. Verify behaviour is unchanged.
package expo

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://exp.host"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// tokenRe is intentionally fixed-length at 32 chars. Expo PATs are
// 32-char [A-Za-z0-9_-] strings; widening to 30-40 used to swallow
// 40-char git SHAs, 40-char SHA-1 hex digests, JWT mid-segments, and
// other opaque blobs in the same chunk.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9_\-]{32})\b`)

// keywordRe requires "expo" / "eas" with an explicit boundary so we
// don't fire on export / exposure / exposed / exponent / exposing /
// reason / treason / season / measure etc. Concretely we demand one
// of:
//
//	EXPO_TOKEN, EXPO_ACCESS_TOKEN, EXPO-TOKEN (case-insensitive)
//	expo.dev / eas.dev hostnames
//	"expo" or "eas" followed by a separator that English prose
//	   wouldn't put there (`:`, `=`, ` token`, ` pat`)
//
// The regex is case-insensitive and is intentionally tight: the
// detector will under-fire on weird wrappers rather than over-fire on
// arbitrary "export" lines.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`expo[_\-]token` +
	`|expo[_\-]access[_\-]token` +
	`|eas[_\-]token` +
	`|eas[_\-]access[_\-]token` +
	`|\bexpo\.dev\b` +
	`|\beas\.dev\b` +
	`|\bexpo[ \t]+(?:token|pat|access)\b` +
	`|\beas[ \t]+(?:token|pat|access)\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Expo }

// Keywords returns the prefilter strings used by the engine's keyword
// pre-scanner. The engine looks for any of these (case-insensitive
// substring) before invoking FromData, so they must be permissive
// enough to admit every chunk a real token might appear in, while
// the in-detector keywordRe enforces the strict shape afterwards.
// We deliberately include both "expo" and "eas" — keywordRe rejects
// the false positives.
func (Scanner) Keywords() []string { return []string{"expo", "eas"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	// Pre-compute keyword match positions once so every candidate
	// can run a constant-time window check.
	kwSpans := keywordRe.FindAllIndex(data, -1)
	if len(kwSpans) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(kwSpans, h[2], h[3]) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.Expo,
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
	return out, nil
}

// nearKeyword reports whether any precomputed keyword span lies
// within ±radius bytes of [start, end). Radius is intentionally tight
// (96) because keywordRe already requires an Expo-specific token, so
// a wide window only adds drift across unrelated lines.
func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		// sp = [kwStart, kwEnd]; overlap or proximity check.
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/v2/auth/userInfo", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	return false, nil
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
