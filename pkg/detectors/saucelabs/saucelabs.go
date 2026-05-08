// Package saucelabs detects Sauce Labs (saucelabs.com) username +
// access_key pairs near the `saucelabs` / `sauce-labs` keyword. Verified
// via /rest/v1/users/{user} on api.us-west-1.saucelabs.com using HTTP
// Basic auth (username:access_key). Raw=username, RawV2=username:access_key
// per the trufflehog convention.
package saucelabs

import (
	"context"
	"encoding/base64"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.us-west-1.saucelabs.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

// Sauce Labs access_keys are UUIDs (`8-4-4-4-12` hex). Username is alnum/_-.
var userRe = regexp.MustCompile(`(?i)SAUCE_USERNAME["\s:=]+([A-Za-z0-9._-]{3,40})`)
var keyRe = regexp.MustCompile(`(?i)SAUCE_ACCESS_KEY["\s:=]+([A-Fa-f0-9-]{32,40})`)

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.SauceLabs }

func (Scanner) Keywords() []string { return []string{"saucelabs", "SAUCE_ACCESS_KEY"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	uMatches := userRe.FindAllSubmatch(data, -1)
	kMatches := keyRe.FindAllSubmatch(data, -1)
	if len(uMatches) == 0 || len(kMatches) == 0 {
		return nil, nil
	}
	user := string(uMatches[0][1])
	key := string(kMatches[0][1])
	res := detectors.Result{
		DetectorType: detectors.SauceLabs,
		Raw:          []byte(user),
		RawV2:        []byte(user + ":" + key),
		Redacted:     redact(user),
	}
	if verify {
		v, err := s.Verify(ctx, user+":"+key)
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/rest/v1/users/"+user, nil)
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
