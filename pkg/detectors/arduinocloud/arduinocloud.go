// Package arduinocloud detects Arduino IoT Cloud client credentials —
// long alnum strings near an `arduino` keyword. Verified via
// /iot/v1/users/byme on api2.arduino.cc with Authorization Bearer.
//
// FP hardening (recall-safe / inconclusive-research path): Arduino does not
// publish the length or charset of the API client_secret — its docs show only
// `YOUR_SECRET_ID` placeholders, with no example credential. The documented
// 32-char hex client_id is the public id, not the secret. With no authoritative
// format to pin, we DELIBERATELY keep the broad `[A-Za-z0-9]{32,80}` regex
// (pinning a length here would silently destroy recall) and instead tighten the
// two recall-safe gates: (1) replace the radius-256 bare `strings.Contains(...,
// "arduino")` with an assignment-style arm regex inside a tight 64-byte window,
// and (2) add a CONSERVATIVE Shannon-entropy floor of 3.0. The bare keyword
// stays in Keywords() as the engine prefilter.
package arduinocloud

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

var apiBase = "https://api2.arduino.cc"

var httpClient = &http.Client{Timeout: 10 * time.Second}

var tokenRe = regexp.MustCompile(`\b([A-Za-z0-9]{32,80})\b`)

// armRe is the assignment-style Arduino credential reference that must appear
// within the proximity window. A bare "arduino" substring is far too weak a
// gate for a 32-80 char alnum run, which collides with hashes, base64 blobs,
// and object ids. The arm
// matches `arduino[_-]?(api[_-]?)?(client[_-]?)?(secret|token|key|id)` — the
// shape a real ARDUINO_API_CLIENT_SECRET / ARDUINO_CLIENT_SECRET assignment or
// config key takes.
var armRe = regexp.MustCompile(`(?i)arduino[_-]?(api[_-]?)?(client[_-]?)?(secret|token|key|id)`)

// minEntropy rejects low-information 32-80 char runs that clear the alnum regex
// but are not random credentials. 3.0 is conservative on purpose: the Arduino
// secret format is undocumented and may be partly hex (entropy caps ~3.6), so
// a 3.5 floor would risk culling real secrets. See package doc.
const minEntropy = 3.0

type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.ArduinoCloud }

func (Scanner) Keywords() []string { return []string{"arduino"} }

func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := tokenRe.FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	lower := strings.ToLower(string(data))
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		token := string(data[h[2]:h[3]])
		if _, dup := seen[token]; dup {
			continue
		}
		if !nearKeyword(lower, h[2], h[3]) {
			continue
		}
		// Conservative entropy gate: low-information 32-80 char runs are
		// rejected even when armed.
		if !detectors.HasMinEntropy(token, minEntropy) {
			continue
		}
		seen[token] = struct{}{}
		res := detectors.Result{
			DetectorType: detectors.ArduinoCloud,
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

// nearKeyword reports whether an Arduino credential-assignment reference (per
// armRe) appears within a tight window on either side of the token. The window
// spans both directions (not strict immediate precedence) so a secret defined
// alongside a nearby ARDUINO_API_CLIENT_SECRET reference still arms.
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
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(apiBase, "/")+"/iot/v1/users/byme", nil)
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
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "..."
}

func init() {
	detectors.Register(Scanner{})
}
