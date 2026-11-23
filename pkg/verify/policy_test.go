package verify

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseDetectorRPS(t *testing.T) {
	m, err := ParseDetectorRPS([]string{"AWS=2", " github = 0 "})
	if err != nil || m["aws"] != 2 || m["github"] != 0 {
		t.Fatalf("got %v %v", m, err)
	}
	for _, bad := range []string{"aws", "=3", "aws=x", "aws=-1"} {
		if _, err := ParseDetectorRPS([]string{bad}); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if (Policy{Retries: 6}).Validate() == nil || (Policy{Timeout: -1}).Validate() == nil {
		t.Fatal("out-of-range policy accepted")
	}
}

func TestPolicyTransportRetriesTransientStatus(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != "payload" && r.Method == http.MethodPost {
			t.Errorf("body not replayed: %q", b)
		}
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	c := &http.Client{Transport: NewPolicyTransport(http.DefaultTransport, Policy{Retries: 2, Backoff: time.Millisecond})}
	resp, err := c.Post(srv.URL, "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || hits.Load() != 3 {
		t.Fatalf("status %d after %d hits", resp.StatusCode, hits.Load())
	}
	// Exhausted retries surface the last transient response.
	hits.Store(-10)
	c = &http.Client{Transport: NewPolicyTransport(http.DefaultTransport, Policy{Retries: 1, Backoff: time.Millisecond})}
	resp, err = c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || hits.Load() != -8 {
		t.Fatalf("status %d hits %d", resp.StatusCode, hits.Load())
	}
}

func TestPolicyTransportTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	defer srv.Close()
	c := &http.Client{Transport: NewPolicyTransport(http.DefaultTransport, Policy{Timeout: 50 * time.Millisecond})}
	start := time.Now()
	if _, err := c.Get(srv.URL); err == nil {
		t.Fatal("want timeout error")
	}
	if time.Since(start) > time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestPolicyTransportDetectorRPSOverride(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	tr := NewPolicyTransport(http.DefaultTransport, Policy{HostRPS: 1, DetectorRPS: map[string]int{"fast": 1000}})
	c := &http.Client{Transport: tr}
	ctx := WithDetector(context.Background(), "FAST")
	start := time.Now()
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if el := time.Since(start); el > 500*time.Millisecond {
		t.Fatalf("detector override ignored; host cap applied (%v)", el)
	}
	if DetectorFrom(ctx) != "fast" {
		t.Fatal("detector tag not normalised")
	}
}
