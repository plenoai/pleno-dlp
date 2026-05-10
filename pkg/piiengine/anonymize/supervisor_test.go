package anonymize

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// httptest spins up a real loopback HTTP server, which is exactly
// what the supervisor expects to talk to. The tests below exercise
// every public method of Supervisor without ever invoking exec —
// they substitute Cmd with a no-op `sleep`-style argv whose stdout
// we don't care about, OR they bypass spawn entirely by constructing
// a Supervisor directly and pointing it at the httptest URL.
//
// The "directly construct" approach is the heavier surface coverage
// path; the spawn-based path appears only in the spawn integration
// test guarded by a build tag, intentionally not in unit tests.

// fakeEngine wires a httptest.Server with configurable /ready and
// /api/analyze handlers. Tests mutate readyAfter to simulate slow
// model load; analyzeFn to drive the response.
type fakeEngine struct {
	server     *httptest.Server
	readyAfter time.Time

	mu        sync.Mutex
	analyzeFn func(req analyzeRequest) (status int, findings []Finding, raw string)
	hits      atomic.Int64
}

func newFakeEngine(t *testing.T) *fakeEngine {
	t.Helper()
	fe := &fakeEngine{}
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		if time.Now().Before(fe.readyAfter) {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/api/analyze", func(w http.ResponseWriter, r *http.Request) {
		fe.hits.Add(1)
		var req analyzeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fe.mu.Lock()
		fn := fe.analyzeFn
		fe.mu.Unlock()
		status, findings, raw := http.StatusOK, []Finding(nil), ""
		if fn != nil {
			status, findings, raw = fn(req)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if raw != "" {
			_, _ = io.WriteString(w, raw)
			return
		}
		_ = json.NewEncoder(w).Encode(findings)
	})
	fe.server = httptest.NewServer(mux)
	t.Cleanup(fe.server.Close)
	return fe
}

// makeSupervisor returns a Supervisor pre-pointed at fe — bypassing
// the spawn step. Useful when we want to exercise Analyze and the
// concurrency model without managing an exec.Cmd in unit tests.
func makeSupervisor(t *testing.T, fe *fakeEngine) *Supervisor {
	t.Helper()
	u, err := url.Parse(fe.server.URL)
	if err != nil {
		t.Fatalf("parse fake URL: %v", err)
	}
	s, err := New(Config{
		Cmd:            []string{"unused-in-this-test"},
		Host:           u.Hostname(),
		Port:           1, // anything non-zero so Start would skip pickPort
		ReadyTimeout:   2 * time.Second,
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Hot-wire the supervisor: fake Cmd, real httptest URL.
	s.mu.Lock()
	s.baseURL = fe.server.URL
	s.started = true
	s.mu.Unlock()
	return s
}

func TestNew_RejectsEmptyCmd(t *testing.T) {
	_, err := New(Config{})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNew_RejectsPublicHost(t *testing.T) {
	_, err := New(Config{Cmd: []string{"x"}, Host: "0.0.0.0"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for 0.0.0.0, got %v", err)
	}
	_, err = New(Config{Cmd: []string{"x"}, Host: "8.8.8.8"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("expected ErrInvalidConfig for public IP, got %v", err)
	}
}

func TestNew_AcceptsLoopbackVariants(t *testing.T) {
	for _, h := range []string{"", "127.0.0.1", "::1", "localhost"} {
		if _, err := New(Config{Cmd: []string{"x"}, Host: h}); err != nil {
			t.Errorf("New(host=%q) failed: %v", h, err)
		}
	}
}

func TestAnalyze_HappyPath(t *testing.T) {
	fe := newFakeEngine(t)
	fe.analyzeFn = func(req analyzeRequest) (int, []Finding, string) {
		if req.Text == "" {
			return http.StatusBadRequest, nil, ""
		}
		return http.StatusOK, []Finding{
			{EntityType: "EMAIL_ADDRESS", Start: 0, End: 11, Score: 0.99, Text: "foo@bar.com"},
		}, ""
	}

	s := makeSupervisor(t, fe)
	defer func() { _ = s.Stop() }()

	got, err := s.Analyze(context.Background(), "foo@bar.com is an email", "en")
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(got) != 1 || got[0].EntityType != "EMAIL_ADDRESS" {
		t.Fatalf("unexpected findings: %#v", got)
	}
}

func TestAnalyze_NotStarted(t *testing.T) {
	s, err := New(Config{Cmd: []string{"x"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Analyze(context.Background(), "x", ""); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("expected ErrNotStarted, got %v", err)
	}
}

func TestAnalyze_AfterStop(t *testing.T) {
	fe := newFakeEngine(t)
	s := makeSupervisor(t, fe)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := s.Analyze(context.Background(), "x", ""); !errors.Is(err, ErrNotStarted) {
		t.Fatalf("expected ErrNotStarted after Stop, got %v", err)
	}
}

func TestAnalyze_EngineFailure(t *testing.T) {
	fe := newFakeEngine(t)
	fe.analyzeFn = func(_ analyzeRequest) (int, []Finding, string) {
		return http.StatusInternalServerError, nil, `{"error":"boom"}`
	}
	s := makeSupervisor(t, fe)
	defer func() { _ = s.Stop() }()
	_, err := s.Analyze(context.Background(), "x", "en")
	if !errors.Is(err, ErrEngineFailed) {
		t.Fatalf("expected ErrEngineFailed, got %v", err)
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("error should preview body, got %v", err)
	}
}

func TestAnalyze_Concurrent(t *testing.T) {
	// Hits the lifecycle mutex on every call concurrently; under
	// `go test -race` this catches any unsynchronised access to
	// baseURL / hc.
	fe := newFakeEngine(t)
	fe.analyzeFn = func(_ analyzeRequest) (int, []Finding, string) {
		return http.StatusOK, []Finding{{EntityType: "PERSON"}}, ""
	}
	s := makeSupervisor(t, fe)
	defer func() { _ = s.Stop() }()

	const N = 50
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			if _, err := s.Analyze(context.Background(), "concurrent", "en"); err != nil {
				t.Errorf("Analyze: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := fe.hits.Load(); got != N {
		t.Errorf("hits=%d want %d", got, N)
	}
}

func TestStop_Idempotent(t *testing.T) {
	fe := newFakeEngine(t)
	s := makeSupervisor(t, fe)
	if err := s.Stop(); err != nil {
		t.Fatalf("first Stop: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestStop_BeforeStart(t *testing.T) {
	s, err := New(Config{Cmd: []string{"x"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop before Start: %v", err)
	}
}

func TestStop_RaceWithAnalyze(t *testing.T) {
	// Stop while Analyze is in flight on many goroutines. With
	// -race this must report no data races. Some Analyze calls
	// will succeed (got there before Stop); some will fail with
	// ErrNotStarted; some may race the http client and surface
	// connection-level errors. All three are acceptable; the
	// invariant is "no panic, no data race, returns within a
	// reasonable bound".
	fe := newFakeEngine(t)
	fe.analyzeFn = func(_ analyzeRequest) (int, []Finding, string) {
		// Tiny delay to widen the race window.
		time.Sleep(2 * time.Millisecond)
		return http.StatusOK, []Finding{{EntityType: "PERSON"}}, ""
	}
	s := makeSupervisor(t, fe)

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_, _ = s.Analyze(context.Background(), "race", "en")
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	close(stop)
	wg.Wait()
}

func TestPollReady_Timeout(t *testing.T) {
	fe := newFakeEngine(t)
	// Make /ready never return 200 within budget.
	fe.readyAfter = time.Now().Add(time.Hour)

	hc := &http.Client{Timeout: 500 * time.Millisecond}
	err := pollReady(context.Background(), hc, fe.server.URL, 200*time.Millisecond)
	if !errors.Is(err, ErrReadyTimeout) {
		t.Fatalf("expected ErrReadyTimeout, got %v", err)
	}
}

func TestPollReady_BecomesReady(t *testing.T) {
	fe := newFakeEngine(t)
	fe.readyAfter = time.Now().Add(50 * time.Millisecond)

	hc := &http.Client{Timeout: 500 * time.Millisecond}
	if err := pollReady(context.Background(), hc, fe.server.URL, 2*time.Second); err != nil {
		t.Fatalf("pollReady: %v", err)
	}
}

func TestPollReady_RespectsCallerContext(t *testing.T) {
	fe := newFakeEngine(t)
	fe.readyAfter = time.Now().Add(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())

	hc := &http.Client{Timeout: 500 * time.Millisecond}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	err := pollReady(ctx, hc, fe.server.URL, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestSubstitutePort(t *testing.T) {
	// Mirrors the CLI's documented default argv after splitArgv:
	// `pleno-dlp pii-server --port {PORT}` plus a synthetic token
	// proving multi-occurrence substitution (an operator might
	// embed {PORT} in a key=value style).
	in := []string{"pleno-dlp", "pii-server", "--port", "{PORT}", "--readiness=:{PORT}/ready"}
	out := substitutePort(in, 41234)
	want := []string{"pleno-dlp", "pii-server", "--port", "41234", "--readiness=:41234/ready"}
	if len(out) != len(want) {
		t.Fatalf("len mismatch: %d vs %d", len(out), len(want))
	}
	for i := range out {
		if out[i] != want[i] {
			t.Errorf("argv[%d]=%q want %q", i, out[i], want[i])
		}
	}
}

func TestPickPort_LoopbackOnly(t *testing.T) {
	p, err := pickPort("127.0.0.1")
	if err != nil {
		t.Fatalf("pickPort: %v", err)
	}
	if p == 0 {
		t.Errorf("pickPort returned 0")
	}
}

func TestSetDefault_Roundtrip(t *testing.T) {
	// SetDefault state is process-global; clean up after ourselves
	// so the next test in this package doesn't observe leftover.
	t.Cleanup(func() { SetDefault(nil) })

	if got := Default(); got != nil {
		t.Fatalf("Default initially %v, want nil", got)
	}
	s, err := New(Config{Cmd: []string{"x"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	SetDefault(s)
	if got := Default(); got != s {
		t.Errorf("Default after Set: got %p want %p", got, s)
	}
	SetDefault(nil)
	if got := Default(); got != nil {
		t.Errorf("Default after reset: got %v want nil", got)
	}
}

// TestStart_SpawnFailure exercises the real exec path with a binary
// that is guaranteed not to exist. We do this here (rather than only
// in integration tests) because spawn-failure is the most likely
// real-world error the engine wiring layer needs to recover from,
// and the unit must verify that ErrSpawnFailed wraps the underlying
// error rather than swallowing it.
func TestStart_SpawnFailure(t *testing.T) {
	s, err := New(Config{
		Cmd:          []string{"/nonexistent-pleno-anonymize-binary-xyzzy"},
		ReadyTimeout: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Start(context.Background())
	if !errors.Is(err, ErrSpawnFailed) {
		t.Fatalf("expected ErrSpawnFailed, got %v", err)
	}
	// Stop should be a safe no-op even after a failed Start.
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop after failed Start: %v", err)
	}
}
