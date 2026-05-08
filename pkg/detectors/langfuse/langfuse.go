// Package langfuse detects Langfuse (langfuse.com) public + secret key
// pairs (`pk-lf-` + `sk-lf-` prefixes) near the `langfuse` keyword.
// Verified via /api/public/projects on cloud.langfuse.com using HTTP
// Basic auth (public_key:secret_key). Raw=public_key,
// RawV2=public_key:secret_key per the trufflehog convention.
package langfuse

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://cloud.langfuse.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Langfuse keys: pk-lf-<uuid> and sk-lf-<uuid>.
var pubRe = regexp.MustCompile(`\b(pk-lf-[a-f0-9-]{30,40})\b`)
var secRe = regexp.MustCompile(`\b(sk-lf-[a-f0-9-]{30,40})\b`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Langfuse }

func (Scanner) Keywords() []string { return []string{"pk-lf-", "sk-lf-"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	pubMatches := pubRe.FindAllSubmatch(data, -1)
	secMatches := secRe.FindAllSubmatch(data, -1)
	if len(pubMatches) == 0 || len(secMatches) == 0 {
		return nil, nil
	}
	pub := string(pubMatches[0][1])
	sec := string(secMatches[0][1])
	res := detectors.Result{
		DetectorType: detectors.Langfuse,
		Raw:          []byte(pub),
		RawV2:        []byte(pub + ":" + sec),
		Redacted:     redact(pub),
	}
	if verify {
		v, err := s.Verify(ctx, pub+":"+sec)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	pub, sec := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/api/public/projects", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(pub + ":" + sec))
	req.Header.Set("Authorization", "Basic "+auth)
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
	if len(t) <= 12 {
		return t
	}
	return t[:12] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
