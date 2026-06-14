// Package verify provides shared HTTP infrastructure for detector verification.
package verify

import (
	"context"
	"net/http"
	"sync"
	"time"
)

type clock interface {
	Now() time.Time
	NewTimer(d time.Duration) *time.Timer
}

type realClock struct{}

func (realClock) Now() time.Time                       { return time.Now() }
func (realClock) NewTimer(d time.Duration) *time.Timer { return time.NewTimer(d) }

// HostLimiter enforces a per-host RPS cap.
type HostLimiter struct {
	rps   int
	clock clock

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	next time.Time
}

func NewHostLimiter(rps int) *HostLimiter {
	return &HostLimiter{rps: rps, clock: realClock{}, buckets: map[string]*bucket{}}
}

func (h *HostLimiter) Wait(host string) time.Time {
	t, _ := h.WaitCtx(context.Background(), host)
	return t
}

func (h *HostLimiter) WaitCtx(ctx context.Context, host string) (time.Time, error) {
	if h == nil || h.rps <= 0 {
		return h.now(), nil
	}
	h.mu.Lock()
	b, ok := h.buckets[host]
	if !ok {
		b = &bucket{}
		h.buckets[host] = b
	}
	now := h.now()
	if now.Before(b.next) {
		sleep := b.next.Sub(now)
		interval := time.Second / time.Duration(h.rps)
		b.next = b.next.Add(interval)
		started := b.next.Add(-interval)
		h.mu.Unlock()
		timer := h.clock.NewTimer(sleep)
		defer timer.Stop()
		select {
		case <-timer.C:
			return started, nil
		case <-ctx.Done():
			return time.Time{}, ctx.Err()
		}
	}
	interval := time.Second / time.Duration(h.rps)
	b.next = now.Add(interval)
	h.mu.Unlock()
	return now, nil
}

func (h *HostLimiter) now() time.Time {
	if h == nil || h.clock == nil {
		return time.Now()
	}
	return h.clock.Now()
}

// RateLimitedTransport wraps an inner RoundTripper with a HostLimiter.
type RateLimitedTransport struct {
	Inner   http.RoundTripper
	Limiter *HostLimiter
}

func (rt *RateLimitedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.Limiter != nil && req.URL != nil {
		if _, err := rt.Limiter.WaitCtx(req.Context(), req.URL.Host); err != nil {
			return nil, err
		}
	}
	inner := rt.Inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	return inner.RoundTrip(req)
}

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

func Restore(prev http.RoundTripper) {
	http.DefaultTransport = prev
}
