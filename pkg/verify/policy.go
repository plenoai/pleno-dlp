package verify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type detectorKey struct{}

// WithDetector tags ctx with the detector type name issuing verification
// requests so a Policy transport can apply per-detector limits.
func WithDetector(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, detectorKey{}, strings.ToLower(name))
}

// DetectorFrom returns the detector name set by WithDetector, or "".
func DetectorFrom(ctx context.Context) string {
	s, _ := ctx.Value(detectorKey{}).(string)
	return s
}

// MaxRetries caps Policy.Retries.
const MaxRetries = 5

// Policy configures verification HTTP behaviour on top of the per-host
// limiter: per-detector RPS overrides, retries on transient failures, and a
// per-request timeout.
type Policy struct {
	// HostRPS is the global per-host cap (0 disables).
	HostRPS int
	// DetectorRPS overrides HostRPS for requests tagged with a detector:
	// those requests share one bucket per detector (across hosts).
	DetectorRPS map[string]int
	// Retries is the number of extra attempts on network errors, 429 and
	// 5xx when the request body is replayable.
	Retries int
	// Timeout bounds each attempt (0 = no transport-level timeout).
	Timeout time.Duration
	// Backoff is the base delay doubled per retry (default 250ms).
	Backoff time.Duration
}

// ParseDetectorRPS parses repeated DETECTOR=RPS selectors.
func ParseDetectorRPS(specs []string) (map[string]int, error) {
	out := map[string]int{}
	for _, spec := range specs {
		name, val, ok := strings.Cut(spec, "=")
		name = strings.ToLower(strings.TrimSpace(name))
		n, err := strconv.Atoi(strings.TrimSpace(val))
		if !ok || name == "" || err != nil || n < 0 {
			return nil, fmt.Errorf("invalid DETECTOR=RPS selector %q", spec)
		}
		out[name] = n
	}
	return out, nil
}

// Validate rejects out-of-range values.
func (p Policy) Validate() error {
	if p.Retries < 0 || p.Retries > MaxRetries {
		return fmt.Errorf("verification retries must be in 0..%d (got %d)", MaxRetries, p.Retries)
	}
	if p.Timeout < 0 {
		return fmt.Errorf("verification timeout must not be negative")
	}
	return nil
}

// PolicyTransport applies a Policy around Inner.
type PolicyTransport struct {
	Inner  http.RoundTripper
	policy Policy
	host   *HostLimiter

	mu        sync.Mutex
	detectors map[string]*HostLimiter
}

// NewPolicyTransport builds a PolicyTransport.
func NewPolicyTransport(inner http.RoundTripper, p Policy) *PolicyTransport {
	if p.Backoff <= 0 {
		p.Backoff = 250 * time.Millisecond
	}
	return &PolicyTransport{Inner: inner, policy: p, host: NewHostLimiter(p.HostRPS), detectors: map[string]*HostLimiter{}}
}

func (t *PolicyTransport) wait(req *http.Request) error {
	if req.URL == nil {
		return nil
	}
	if det := DetectorFrom(req.Context()); det != "" {
		if rps, ok := t.policy.DetectorRPS[det]; ok {
			t.mu.Lock()
			l := t.detectors[det]
			if l == nil {
				l = NewHostLimiter(rps)
				t.detectors[det] = l
			}
			t.mu.Unlock()
			_, err := l.WaitCtx(req.Context(), det)
			return err
		}
	}
	_, err := t.host.WaitCtx(req.Context(), req.URL.Host)
	return err
}

func (t *PolicyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	inner := t.Inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	attempts := 1
	if replayable {
		attempts += t.policy.Retries
	}
	var lastErr error
	for i := 0; i < attempts; i++ {
		if i > 0 {
			delay := t.policy.Backoff << (i - 1)
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			}
		}
		attempt := req
		if i > 0 && req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			attempt = req.Clone(req.Context())
			attempt.Body = body
		}
		if err := t.wait(attempt); err != nil {
			return nil, err
		}
		resp, err := t.once(inner, attempt)
		last := i == attempts-1
		switch {
		case err != nil:
			if req.Context().Err() != nil {
				return nil, err
			}
			lastErr = err
			if last {
				return nil, err
			}
		case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
			if last {
				return resp, nil
			}
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
			_ = resp.Body.Close()
		default:
			return resp, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("verify: retries exhausted")
	}
	return nil, lastErr
}

func (t *PolicyTransport) once(inner http.RoundTripper, req *http.Request) (*http.Response, error) {
	if t.policy.Timeout <= 0 {
		return inner.RoundTrip(req)
	}
	ctx, cancel := context.WithTimeout(req.Context(), t.policy.Timeout)
	resp, err := inner.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// InstallPolicy replaces http.DefaultTransport with a PolicyTransport and
// returns the previous transport for Restore. A zero policy (no limits,
// retries, or timeout) leaves the transport untouched.
func InstallPolicy(p Policy) http.RoundTripper {
	prev := http.DefaultTransport
	if p.HostRPS <= 0 && len(p.DetectorRPS) == 0 && p.Retries == 0 && p.Timeout == 0 {
		return prev
	}
	http.DefaultTransport = NewPolicyTransport(prev, p)
	return prev
}
