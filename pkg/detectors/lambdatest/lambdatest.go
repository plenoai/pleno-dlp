// Package lambdatest detects LambdaTest username + access_key pairs
// near the `lambdatest` keyword. Verified via /automation/api/v1/builds
// on api.lambdatest.com using HTTP Basic auth (username:access_key).
// Raw=username, RawV2=username:access_key per the trufflehog convention.
package lambdatest

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.lambdatest.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// LambdaTest usernames are typically email-prefix or short alnum strings;
// access_keys are 20-32 alnum chars. We pair a `LT_USERNAME=` shape with
// a `LT_ACCESS_KEY=` shape — the same chunk almost always has both.
var userRe = regexp.MustCompile(`(?i)LT_USERNAME["\s:=]+([A-Za-z0-9._-]{3,40})`)
var keyRe = regexp.MustCompile(`(?i)LT_ACCESS_KEY["\s:=]+([A-Za-z0-9]{20,40})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.LambdaTest }

func (Scanner) Keywords() []string { return []string{"lambdatest", "LT_ACCESS_KEY"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	uMatches := userRe.FindAllSubmatch(data, -1)
	kMatches := keyRe.FindAllSubmatch(data, -1)
	if len(uMatches) == 0 || len(kMatches) == 0 {
		return nil, nil
	}
	username := string(uMatches[0][1])
	accessKey := string(kMatches[0][1])
	res := detectors.Result{
		DetectorType: detectors.LambdaTest,
		Raw:          []byte(username),
		RawV2:        []byte(username + ":" + accessKey),
		Redacted:     redact(username),
	}
	if verify {
		v, err := s.Verify(ctx, username+":"+accessKey)
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
	user, key := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/automation/api/v1/builds", nil)
	if err != nil {
		return false, err
	}
	auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + key))
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
	if len(t) <= 4 {
		return t
	}
	return t[:4] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
