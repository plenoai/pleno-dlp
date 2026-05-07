// Package verify provides shared HTTP infrastructure for detector
// verification. The headline feature is `Install(rps)`, which swaps
// http.DefaultTransport with a per-host rate-limited RoundTripper —
// every detector that uses the default http.Client (which is all of
// them) automatically gets rate-limiting without per-detector edits.
//
// Why per-host: a real scan with `--verify` against a thousand-key
// dump would otherwise hammer one provider with a thousand
// concurrent requests, triggering rate-limit responses, IP bans,
// and quota-burn paged to the operator. Per-host (rather than
// global) limiting is the right granularity because providers
// each enforce their own quota independently.
package verify

import (
	"net/http"
	"sync"
	"time"
)

// HostLimiter enforces a per-host RPS cap via simple token-bucket
// math (no goroutines, no external deps). Burst capacity equals one
// second's worth of tokens — enough to absorb spiky launches without
// inviting bursty backlog.
type HostLimiter struct {
	rps int

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	// next is the wall-clock time at which the next token is
	// available. Per-call: if now >= next, allow immediately and
	// advance next by 1/rps; else block until next.
	next time.Time
}

// NewHostLimiter returns a limiter with the given per-host RPS.
// rps <= 0 disables rate limiting (every Wait returns immediately).
func NewHostLimiter(rps int) *HostLimiter {
	return &HostLimiter{rps: rps, buckets: map[string]*bucket{}}
}

// Wait blocks until the limiter authorises a request to host. Returns
// the time at which the request is allowed to proceed; callers can
// observe this for jitter/diagnostic purposes. Cheap (no allocs) on
// the hot path once the bucket is initialised.
func (h *HostLimiter) Wait(host string) time.Time {
	if h == nil || h.rps <= 0 {
		return time.Now()
	}
	h.mu.Lock()
	b, ok := h.buckets[host]
	if !ok {
		b = &bucket{}
		h.buckets[host] = b
	}
	now := time.Now()
	if now.Before(b.next) {
		sleep := b.next.Sub(now)
		// Advance next by one slot for THIS request before
		// releasing the lock so concurrent callers stack
		// correctly behind us.
		interval := time.Second / time.Duration(h.rps)
		b.next = b.next.Add(interval)
		h.mu.Unlock()
		time.Sleep(sleep)
		return b.next.Add(-interval) // approximate "started at"
	}
	// Bucket is fresh / aged out: slot starts now, next slot one
	// interval ahead.
	interval := time.Second / time.Duration(h.rps)
	b.next = now.Add(interval)
	h.mu.Unlock()
	return now
}

// RateLimitedTransport wraps an inner RoundTripper with a HostLimiter.
// req.URL.Host is the rate-limit key — vendor subdomains (e.g.
// `api.stripe.com` vs `dashboard.stripe.com`) are limited
// independently, which is correct because providers usually rate-limit
// per FQDN.
type RateLimitedTransport struct {
	Inner   http.RoundTripper
	Limiter *HostLimiter
}

func (rt *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.Limiter != nil && req.URL != nil {
		rt.Limiter.Wait(req.URL.Host)
	}
	inner := rt.Inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(req)
}

// Install swaps http.DefaultTransport with a RateLimitedTransport so
// every detector that uses the default http.Client (which is all of
// them — none override Transport) gets rate-limited. rps <= 0 is a
// no-op so callers don't need to special-case "rate limiting off".
//
// Callers MUST invoke this before any detector runs; the swap is
// process-wide and not intended to flip mid-scan. Returns the
// previous transport so test code can restore the default.
func Install(rps int) http.RoundTripper {
	if rps <= 0 {
		return http.DefaultTransport
	}
	prev := http.DefaultTransport
	http.DefaultTransport = &RateLimitedTransport{
		Inner:   prev,
		Limiter: NewHostLimiter(rps),
	}
	return prev
}

// Restore swaps http.DefaultTransport back to prev. Tests use this in
// t.Cleanup to keep state between subtests sane.
func Restore(prev http.RoundTripper) {
	http.DefaultTransport = prev
}
