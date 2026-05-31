// Package copper detects Copper CRM credentials — user_email +
// access_token pair near the `copper` keyword. Verified via
// /developer_api/v1/account on api.copper.com using X-PW-AccessToken,
// X-PW-Application, and X-PW-UserEmail headers. Raw carries the email,
// RawV2 the token.
package copper

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api.copper.com"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var emailRe = regexp.MustCompile(`\b([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})\b`)

// Copper API keys are 32-char lowercase-hex strings, per the upstream
// trufflehog detector (PrefixRegex(["copper"]) + \b([a-z0-9]{32})\b).
// Copper's own docs do not publish the format, so trufflehog is the
// authoritative shape we mirror: fixed length 32, charset [a-z0-9].
// The previous bare [A-Za-z0-9]{32,128} matched commit SHAs, base64url
// nonces, k8s object names, and arbitrary high-entropy blobs.
var tokenRe = regexp.MustCompile(`\b([a-z0-9]{32})\b`)

// armRe is the assignment-style Copper reference that must appear within
// the proximity window of the token. A bare "copper" substring (the CSS
// color, the metal, dependency names, comments) is far too weak;
// "copper_api_token" / "copper-key" / "coppersecret" is the shape a real
// credential assignment or config key takes. The bare "copper" keyword
// stays in Keywords() as the engine prefilter.
var armRe = regexp.MustCompile(`(?i)copper[_\-]?(api[_\-]?)?(token|key|secret)`)

// minEntropy is the hex floor (alphabet 16 → ceiling ~4.0). 3.5 would
// over-cull legitimate hex tokens; 3.0 still rejects runs of zeros,
// repeated nibbles, and other low-information 32-char hex garbage.
const minEntropy = 3.0

var contextKeywords = []string{"copper"}

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.Copper }

func (Scanner) Keywords() []string { return []string{"copper"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	emails := emailRe.FindAllSubmatchIndex(data, -1)
	tokens := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(emails) == 0 || len(tokens) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	var email string
	for _, h := range emails {
		if !nearCopper(lower, h[2], h[3]) {
			continue
		}
		email = string(data[h[2]:h[3]])
		break
	}
	if email == "" {
		return nil, nil
	}
	var token string
	for _, h := range tokens {
		// The token half carries the assignment anchor: a
		// copper[_-]?(api[_-]?)?(token|key|secret) reference must sit
		// within a tight window of the candidate. 32-char lowercase-hex
		// runs are common (md5 digests, git blob hashes), so proximity
		// to a bare "copper" alone is not enough.
		if !nearArm(lower, h[2], h[3]) {
			continue
		}
		v := string(data[h[2]:h[3]])
		if v == email {
			continue
		}
		// Entropy floor rejects structured/low-information 32-char hex
		// runs (zero-padding, repeated nibbles) that clear the regex.
		if !detectors.HasMinEntropy(v, minEntropy) {
			continue
		}
		token = v
		break
	}
	if token == "" {
		return nil, nil
	}
	res := detectors.Result{
		DetectorType: detectors.Copper,
		Raw:          []byte(email),
		RawV2:        []byte(token),
		Redacted:     redact(email),
	}
	if verify {
		v, err := s.Verify(ctx, email+":"+token)
		res.Verified = v
		res.VerificationErr = err
	}
	return []detectors.Result{res}, nil
}

// radius bounds both proximity gates. Tightened from 256 to 64: at 256 a
// "copper" anywhere in a ~half-kilobyte span armed the detector, which is
// what let unrelated hex/email pairs through.
const radius = 64

// window returns the lower-cased span [start-radius, end+radius] clamped
// to the data bounds.
func window(lower string, start, end int) string {
	from := start - radius
	if from < 0 {
		from = 0
	}
	to := end + radius
	if to > len(lower) {
		to = len(lower)
	}
	return lower[from:to]
}

// nearCopper gates the email half: a bare "copper" reference within the
// tight window. The email itself is the weaker signal in the pair, so it
// only needs proximity to the vendor keyword, not the full arm anchor.
func nearCopper(lower string, start, end int) bool {
	w := window(lower, start, end)
	for _, kw := range contextKeywords {
		if strings.Contains(w, kw) {
			return true
		}
	}
	return false
}

// nearArm gates the token half: a copper[_-]?(api[_-]?)?(token|key|secret)
// assignment-style reference within the tight window.
func nearArm(lower string, start, end int) bool {
	return armRe.MatchString(window(lower, start, end))
}

func (Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 {
		return false, nil
	}
	email, token := parts[0], parts[1]
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/developer_api/v1/account", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("X-PW-AccessToken", token)
	req.Header.Set("X-PW-Application", "developer_api")
	req.Header.Set("X-PW-UserEmail", email)
	req.Header.Set("Content-Type", "application/json")
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
