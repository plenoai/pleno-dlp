package verify

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) NewTimer(d time.Duration) *time.Timer {
	c.advance(d)
	t := time.NewTimer(0)
	return t
}

func newFakeLimiter(rps int) (*HostLimiter, *fakeClock) {
	fc := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l := &HostLimiter{rps: rps, clock: fc, buckets: map[string]*bucket{}}
	return l, fc
}

func TestHostLimiter_Disabled_Passthrough(t *testing.T) {
	l := NewHostLimiter(0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		l.Wait("example.com")
	}
	if took := time.Since(start); took > 50*time.Millisecond {
		t.Errorf("disabled limiter must be ~free, took %v", took)
	}
}

func TestHostLimiter_RatePer_Host(t *testing.T) {
	l, _ := newFakeLimiter(5)
	for i := 0; i < 5; i++ {
		l.Wait("a.example")
	}
}

func TestHostLimiter_PerHost_Independence(t *testing.T) {
	l, _ := newFakeLimiter(2)
	l.Wait("a.example")
	l.Wait("b.example")
	l.Wait("a.example")
	l.Wait("b.example")
}

func TestHostLimiter_BucketMath(t *testing.T) {
	l, fc := newFakeLimiter(10)
	t1 := l.Wait("host")
	t2 := l.Wait("host")
	interval := t2.Sub(t1)
	if interval != 100*time.Millisecond {
		t.Errorf("expected 100ms interval at 10rps, got %v", interval)
	}
	fc.advance(time.Second)
	t3 := l.Wait("host")
	_ = t3
}

func TestRateLimitedTransport_DelegatesAndLimits(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	l, _ := newFakeLimiter(10)
	tr := &RateLimitedTransport{
		Inner:   http.DefaultTransport,
		Limiter: l,
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	if got := atomic.LoadInt64(&hits); got != 10 {
		t.Errorf("expected 10 hits, got %d", got)
	}
}

func TestInstall_RestoresDefault(t *testing.T) {
	prev := Install(50)
	t.Cleanup(func() { Restore(prev) })

	if _, ok := http.DefaultTransport.(*RateLimitedTransport); !ok {
		t.Fatalf("Install should have wrapped DefaultTransport, got %T", http.DefaultTransport)
	}
	Restore(prev)
	if _, ok := http.DefaultTransport.(*RateLimitedTransport); ok {
		t.Error("Restore should have unwrapped DefaultTransport")
	}
}

func TestInstall_NoOpOnZero(t *testing.T) {
	prev := http.DefaultTransport
	got := Install(0)
	if got != prev {
		t.Errorf("Install(0) must return the unmodified transport, got different RoundTripper")
	}
	if http.DefaultTransport != prev {
		t.Errorf("Install(0) must NOT swap DefaultTransport")
	}
}
