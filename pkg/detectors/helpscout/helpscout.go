package helpscout

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.helpscout.net"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,128})\b`)

// armRe gates on an assignment-shaped helpscout reference. Help Scout does not
// document the App ID/Secret length or charset, so we pin no length and require
// this arm shape within a radius-64 window instead of a bare keyword match.
var armRe = regexp.MustCompile(`(?i)helpscout[_\-]?(app[_\-]?)?(id|key|token|secret|client)`)

// minEntropy rejects low-information 32-128 char runs that clear the alnum
// regex but are not random tokens. Help Scout credentials are hex-like, so we
// use a conservative 3.0 floor (hex caps ~3.6; 3.5 would over-cull) to protect recall.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.HelpScout }

func (Scanner) Keywords() []string { return []string{"helpscout"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) < 2 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	creds := make([]string, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if _, dup := seen[v]; dup {
			continue
		}
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		seen[v] = struct{}{}
		creds = append(creds, v)
	}
	if len(creds) < 2 {
		return nil, nil
	}
	id, secret := creds[0], creds[1]
	res := detectors.Result{
		DetectorType: detectors.HelpScout,
		Raw:          []byte(id),
		RawV2:        []byte(secret),
		Redacted:     redact(id),
	}
	if verify {
		v, err := s.Verify(ctx, id+":"+secret)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// nearKeyword reports whether an armRe reference appears within a tight window
// on either side of the candidate.
func nearKeyword(lower string, start, end int) bool {
	const radius = 64
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return armRe.MatchString(lower[from:to])
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	id, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body := strings.NewReader("grant_type=client_credentials&client_id=" + id + "&client_secret=" + sec)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(apiBase, "/")+"/v2/oauth2/token", body)
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
