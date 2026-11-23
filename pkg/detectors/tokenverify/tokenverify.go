// Package tokenverify builds a Detector + Verifier from a declarative
// Spec: one RE2 pattern whose first capture group is the secret, and one
// HTTP request whose response is classified by ordered status/body rules.
// It exists so that single-request token formats (the bulk of the
// Betterleaks catalog kingfisher ships, see docs/kingfisher-parity.md)
// need a spec and a test rather than a hand-copied scanner.
//
// Classification never collapses ambiguity into a negative: a response
// that matches no Valid or Invalid rule is a verification error, and 429
// or 5xx is reported as transient — the same contract as
// detectors.ClassifyVerifyHTTP.
package tokenverify

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// maxBody caps how much of a verification response is inspected.
const maxBody = 64 << 10

const timeout = 10 * time.Second

var httpClient = detectors.NewVerifyHTTPClient(timeout)

// Auth places the secret on the request.
type Auth func(r *http.Request, secret string)

// Bearer sets "Authorization: Bearer <secret>".
func Bearer() Auth { return Header("Authorization", "Bearer ") }

// Header sets name to prefix+secret.
func Header(name, prefix string) Auth {
	return func(r *http.Request, s string) { r.Header.Set(name, prefix+s) }
}

// BasicUser sends the secret as the Basic-auth username with an empty password.
func BasicUser() Auth { return func(r *http.Request, s string) { r.SetBasicAuth(s, "") } }

// BasicPassword sends the secret as the Basic-auth password for user.
func BasicPassword(user string) Auth {
	return func(r *http.Request, s string) { r.SetBasicAuth(user, s) }
}

// BasicRaw sends "Authorization: Basic base64(secret)" (the secret already
// carries its own user:password shape, or the provider expects no colon).
func BasicRaw() Auth {
	return func(r *http.Request, s string) {
		r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
	}
}

// Query adds the secret as query parameter name.
func Query(name string) Auth {
	return func(r *http.Request, s string) {
		q := r.URL.Query()
		q.Set(name, s)
		r.URL.RawQuery = q.Encode()
	}
}

// PathSecret marks a Request whose Path contains "{secret}"; the Auth is a no-op.
func PathSecret() Auth { return func(*http.Request, string) {} }

// Rule matches a response. Status 0 matches any status.
type Rule struct {
	Status          int
	BodyContains    string
	BodyNotContains string
}

func (r Rule) match(status int, body []byte) bool {
	if r.Status != 0 && r.Status != status {
		return false
	}
	if r.BodyContains != "" && !bytes.Contains(body, []byte(r.BodyContains)) {
		return false
	}
	if r.BodyNotContains != "" && bytes.Contains(body, []byte(r.BodyNotContains)) {
		return false
	}
	return true
}

// Request describes the single verification round trip.
type Request struct {
	Method  string // default GET
	BaseURL string // scheme://host, overridable in tests via SetBaseURL
	// Path may contain "{secret}" (only with PathSecret); the pattern
	// must then restrict the secret to URL-path-safe characters.
	Path string
	// PathFor, when set, overrides Path per secret (e.g. token-kind
	// specific endpoints selected by prefix).
	PathFor     func(secret string) string
	Auth        Auth
	Headers     map[string]string
	Body        string
	ContentType string
	Valid       []Rule // default: 200
	Invalid     []Rule // default: 401, 403
}

// Spec declares one detector.
type Spec struct {
	Type     detectors.DetectorType
	Keywords []string
	// Pattern is RE2; the first participating capture group is the
	// secret, so alternatives may each carry their own group.
	Pattern string
	// RedactKeep is how many leading characters the redacted form keeps
	// (default 8, capped at half the secret).
	RedactKeep int
	// Validate optionally rejects regex matches offline (e.g. checksums).
	Validate func(secret string) bool
	Verify   Request
	// Assurance defaults to AssuranceProviderConfirmed: every spec's
	// Valid rules must require a response only an authenticated caller
	// receives.
	Assurance detectors.VerificationAssurance
}

// Scanner implements detectors.Detector and detectors.Verifier for a Spec.
type Scanner struct {
	spec Spec
	re   func() *regexp.Regexp
	mu   sync.RWMutex
	base string
}

// New compiles spec lazily and returns its scanner.
func New(spec Spec) *Scanner {
	if spec.Verify.Method == "" {
		spec.Verify.Method = http.MethodGet
	}
	if len(spec.Verify.Valid) == 0 {
		spec.Verify.Valid = []Rule{{Status: http.StatusOK}}
	}
	if len(spec.Verify.Invalid) == 0 {
		spec.Verify.Invalid = []Rule{{Status: http.StatusUnauthorized}, {Status: http.StatusForbidden}}
	}
	if spec.Assurance == detectors.AssuranceUnknown {
		spec.Assurance = detectors.AssuranceProviderConfirmed
	}
	pattern := spec.Pattern
	return &Scanner{
		spec: spec,
		re:   sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(pattern) }),
		base: spec.Verify.BaseURL,
	}
}

// SetBaseURL redirects verification (tests only) and returns a restore func.
func (s *Scanner) SetBaseURL(u string) func() {
	s.mu.Lock()
	old := s.base
	s.base = u
	s.mu.Unlock()
	return func() { s.mu.Lock(); s.base = old; s.mu.Unlock() }
}

// Spec returns a copy of the declaration (for docs and tests).
func (s *Scanner) Spec() Spec { return s.spec }

func (s *Scanner) Type() detectors.DetectorType { return s.spec.Type }

func (s *Scanner) Keywords() []string { return s.spec.Keywords }

func (s *Scanner) MaxVerificationAssurance() detectors.VerificationAssurance {
	return s.spec.Assurance
}

// VerificationCacheUsesFullInput is false: Raw alone determines the verdict.
func (s *Scanner) VerificationCacheUsesFullInput() bool { return false }

func (s *Scanner) FromData(ctx context.Context, verify bool, data []byte) ([]detectors.Result, error) {
	hits := s.re().FindAllSubmatchIndex(data, -1)
	if len(hits) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(hits))
	seen := map[string]struct{}{}
	for _, h := range hits {
		start, end := -1, -1
		for g := 2; g+1 < len(h); g += 2 {
			if h[g] >= 0 {
				start, end = h[g], h[g+1]
				break
			}
		}
		if start < 0 {
			continue
		}
		secret := string(data[start:end])
		if _, dup := seen[secret]; dup {
			continue
		}
		seen[secret] = struct{}{}
		if s.spec.Validate != nil && !s.spec.Validate(secret) {
			continue
		}
		res := detectors.Result{DetectorType: s.spec.Type, Raw: []byte(secret), Redacted: s.redact(secret)}
		if verify {
			res.Verified, res.VerificationErr = s.Verify(ctx, secret)
		}
		out = append(out, res)
	}
	return detectors.SafeResults(out), nil
}

func (s *Scanner) redact(secret string) string {
	keep := s.spec.RedactKeep
	if keep <= 0 {
		keep = 8
	}
	if keep > len(secret)/2 {
		keep = len(secret) / 2
	}
	return secret[:keep] + "..."
}

// Verify performs the declared round trip. Errors never embed the URL or
// headers, which may carry the secret.
func (s *Scanner) Verify(ctx context.Context, secret string) (bool, error) {
	name := s.spec.Type.String()
	if secret == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	v := s.spec.Verify
	s.mu.RLock()
	base := strings.TrimRight(s.base, "/")
	s.mu.RUnlock()
	path := v.Path
	if v.PathFor != nil {
		path = v.PathFor(secret)
	}
	if strings.Contains(path, "{secret}") {
		path = strings.ReplaceAll(path, "{secret}", secret)
	}
	var body io.Reader
	if v.Body != "" {
		body = strings.NewReader(v.Body)
	}
	req, err := http.NewRequestWithContext(ctx, v.Method, base+path, body)
	if err != nil {
		return false, fmt.Errorf("%s verify: build request", name)
	}
	for k, val := range v.Headers {
		req.Header.Set(k, val)
	}
	if v.ContentType != "" {
		req.Header.Set("Content-Type", v.ContentType)
	}
	if v.Auth != nil {
		v.Auth(req, secret)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return false, fmt.Errorf("%s verify: timeout", name)
		}
		return false, fmt.Errorf("%s verify: request failed", name)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return false, fmt.Errorf("%s verify: read response", name)
	}
	return Classify(name, resp.StatusCode, payload, v.Valid, v.Invalid)
}

// Classify maps a response onto the Verifier contract: a Valid rule is
// (true, nil); 429/5xx is a transient error; an Invalid rule is
// (false, nil); anything else is an ambiguous error.
func Classify(name string, status int, body []byte, valid, invalid []Rule) (bool, error) {
	for _, r := range valid {
		if r.match(status, body) {
			return true, nil
		}
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		return false, fmt.Errorf("%s verify: transient HTTP %d", name, status)
	}
	for _, r := range invalid {
		if r.match(status, body) {
			return false, nil
		}
	}
	return false, fmt.Errorf("%s verify: ambiguous HTTP %d", name, status)
}

var (
	_ detectors.Detector                        = (*Scanner)(nil)
	_ detectors.Verifier                        = (*Scanner)(nil)
	_ detectors.VerificationPolicy              = (*Scanner)(nil)
	_ detectors.VerificationCacheInputDependent = (*Scanner)(nil)
)
