// Package characterai detects Character.AI API tokens — long alnum
// strings near the `character` keyword. Verified via /chat/user on
// plus.character.ai with Token auth header.
package characterai

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://plus.character.ai"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([a-f0-9]{40,80})\b`)

// keywordRe is the anchored Character.AI marker. The bare `character`
// substring shows up in any code that mentions characters (encoding
// docs, runes, string handling) and pairs with adjacent SHA-1
// hashes. Require a Character.AI credential anchor.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bcharacter[_\-]ai(?:[_\-](?:api|token|key|secret))?` +
	`|\bcharacter\.ai\b` +
	`|\bplus\.character\.ai\b` +
	`|\bcharacterai(?:[_\-](?:api|token|key|secret))?\b` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.CharacterAI }

func (Scanner) Keywords() []string { return []string{"character"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
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
			DetectorType: detectors.CharacterAI,
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
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func nearKeyword(kwSpans [][]int, start, end int) bool {
	const radius = 96
	from := start - radius
	to := end + radius
	for _, sp := range kwSpans {
		if sp[1] >= from && sp[0] <= to {
			return true
		}
	}
	return false
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/chat/user/", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", "Token "+secret)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
