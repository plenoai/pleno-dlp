// Package harbor detects Harbor container registry CLI secrets / robot
// account passwords near the `harbor` keyword. Unverified by design —
// Harbor is self-hosted per-deployment so verification fires only when
// an apiBase override is supplied (Harbor's /api/v2.0/users/current is
// the canonical probe).
package harbor

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = ""

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Harbor robot accounts have CLI secrets of 16+ alnum chars; we keep the
// upper bound generous because tenants can configure key length.
var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{16,64})\b`)

// keywordRe is the anchored Harbor marker. The bare `harbor` substring
// shows up in English prose (`harbor`/`harbour`, "Pearl Harbor", port
// metaphors) and in goharbor.io documentation prose — both adjacent to
// ≥ 16-char alnum runs (UUIDs, hashes). Require a Harbor-credential
// anchor instead.
var keywordRe = regexp.MustCompile(`(?i)` +
	`(?:` +
	`\bharbor[_\-](?:api|token|key|secret|user|password|cli|robot)` +
	`|\bgoharbor\b` +
	`|\bharbor\.io\b` +
	`|\bharbor[ \t]*[:=]` +
	`|\brobot\$` +
	`)`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Harbor }

func (Scanner) Keywords() []string { return []string{"harbor"} }

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
			DetectorType: detectors.Harbor,
			Raw:          []byte(token),
			Redacted:     redact(token),
		}
		if verify && apiBase != "" {
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
	if apiBase == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/v2.0/users/current", nil)
	if err != nil {
		return false, err
	}
	// Harbor uses HTTP Basic with the robot account name + CLI secret;
	// callers supply only the secret here, so we send it as the password
	// with an empty username — the verify probe is best-effort.
	req.SetBasicAuth("", secret)
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
