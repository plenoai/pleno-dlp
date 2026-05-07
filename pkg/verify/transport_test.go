package verify

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

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
	// 5 RPS = ~200ms per request. 5 sequential calls should take
	// at least ~800ms (4 intervals after the first).
	l := NewHostLimiter(5)
	start := time.Now()
	for i := 0; i < 5; i++ {
		l.Wait("a.example")
	}
	took := time.Since(start)
	if took < 700*time.Millisecond {
		t.Errorf("5 calls at 5rps should take ~800ms, took %v", took)
	}
	if took > 1300*time.Millisecond {
		t.Errorf("5 calls at 5rps must not exceed ~1.2s, took %v", took)
	}
}

func TestHostLimiter_PerHost_Independence(t *testing.T) {
	// Two hosts at 2rps each. 4 calls (2 per host) interleaved
	// should finish in <600ms because each host has its own bucket.
	l := NewHostLimiter(2)
	start := time.Now()
	var wg sync.WaitGroup
	for _, host := range []string{"a.example", "b.example"} {
		host := host
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Wait(host)
			l.Wait(host)
		}()
	}
	wg.Wait()
	if took := time.Since(start); took > 1100*time.Millisecond {
		t.Errorf("per-host independence broken; 2 hosts × 2 calls @ 2rps took %v", took)
	}
}

func TestRateLimitedTransport_DelegatesAndLimits(t *testing.T) {
	// Server records request times so we can assert spacing.
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := &RateLimitedTransport{
		Inner:   http.DefaultTransport,
		Limiter: NewHostLimiter(10), // 10 rps
	}
	c := &http.Client{Transport: tr, Timeout: 5 * time.Second}

	start := time.Now()
	for i := 0; i < 10; i++ {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	took := time.Since(start)
	if took < 800*time.Millisecond {
		t.Errorf("10 calls at 10rps should take ~900ms, took %v", took)
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
