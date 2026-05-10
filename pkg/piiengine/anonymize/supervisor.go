package anonymize

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Supervisor owns the pleno-anonymize child process and the HTTP
// client used to talk to it.
//
// State machine:
//
//	zero → Start → running → Stop → stopped (terminal)
//
// Concurrency model:
//
//   - mu protects the lifecycle fields (cmd, baseURL, started,
//     stopped). It is held only briefly; in particular, it is NOT
//     held across HTTP calls so concurrent Analyze callers cannot
//     serialize on each other.
//   - http.Client is concurrent-safe by stdlib contract.
//   - Stop sets stopped under mu, then closes the http client's
//     idle conns, then signals the child. Any Analyze call that
//     read started==true before stopped flipped will see a clean
//     "context cancelled" or "connection refused" from the http
//     client when its request lands; both surface as wrapped errors
//     to the caller.
type Supervisor struct {
	cfg Config

	hc *http.Client

	mu      sync.Mutex
	cmd     *exec.Cmd
	port    int
	baseURL string
	started bool
	stopped bool
	// done is closed once the child process Wait returns. Used by
	// Stop to bound SIGTERM grace before escalating to SIGKILL
	// without polling.
	done chan struct{}
}

// New constructs a Supervisor from cfg without starting it.
//
// Validates the config eagerly: an empty Cmd or a non-loopback Host
// is rejected here so misconfiguration cannot reach exec(). Defaults
// fill in for unspecified fields so a zero-valued Config minus Cmd
// is usable.
func New(cfg Config) (*Supervisor, error) {
	if len(cfg.Cmd) == 0 {
		return nil, fmt.Errorf("%w: Cmd is required", ErrInvalidConfig)
	}
	if cfg.Host == "" {
		cfg.Host = "127.0.0.1"
	}
	if !isLoopback(cfg.Host) {
		return nil, fmt.Errorf("%w: Host %q is not a loopback address", ErrInvalidConfig, cfg.Host)
	}
	if cfg.ReadyTimeout <= 0 {
		cfg.ReadyTimeout = 60 * time.Second
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = 10 * time.Second
	}
	return &Supervisor{
		cfg: cfg,
		hc: &http.Client{
			Timeout: cfg.RequestTimeout,
		},
		done: make(chan struct{}),
	}, nil
}

// Start spawns the child, waits for /ready, and returns.
//
// Errors are wrapped with the appropriate sentinel
// (ErrSpawnFailed, ErrReadyTimeout) so callers can branch on
// failure mode. On any error the child is killed and the
// Supervisor is left in a state where Stop is a safe no-op.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("anonymize: supervisor already started")
	}
	if s.stopped {
		s.mu.Unlock()
		return fmt.Errorf("anonymize: supervisor already stopped")
	}

	port := s.cfg.Port
	if port == 0 {
		p, err := pickPort(s.cfg.Host)
		if err != nil {
			s.mu.Unlock()
			return fmt.Errorf("%w: %v", ErrSpawnFailed, err)
		}
		port = p
	}
	argv := substitutePort(s.cfg.Cmd, port)
	cmd := buildCmd(argv)
	if cmd == nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: empty argv", ErrSpawnFailed)
	}
	if s.cfg.Stderr != nil {
		cmd.Stderr = s.cfg.Stderr
	} else {
		cmd.Stderr = io.Discard
	}
	cmd.Stdout = io.Discard

	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrSpawnFailed, err)
	}

	s.cmd = cmd
	s.port = port
	s.baseURL = "http://" + net.JoinHostPort(s.cfg.Host, strconv.Itoa(port))
	s.started = true
	s.mu.Unlock()

	// Reap the child in the background so Wait returns deterministically
	// once Stop signals the process. Closing done lets Stop bound the
	// SIGTERM grace window without polling Process.Signal(0).
	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()

	// Block until /ready returns 200. If the child crashes during
	// startup, the next readyOnce attempt fails with connection
	// refused; pollReady's deadline still bounds the wait.
	if err := pollReady(ctx, s.hc, s.baseURL, s.cfg.ReadyTimeout); err != nil {
		// Best-effort tear-down. We ignore Stop's error because we
		// already have a more meaningful one to return.
		_ = s.Stop()
		return err
	}
	return nil
}

// Analyze posts text to /api/analyze and returns parsed findings.
// Safe for concurrent use across goroutines.
//
// language overrides Config.Language for this call only; pass "" to
// fall back to the configured default.
func (s *Supervisor) Analyze(ctx context.Context, text, language string) ([]Finding, error) {
	s.mu.Lock()
	if !s.started || s.stopped {
		s.mu.Unlock()
		return nil, ErrNotStarted
	}
	baseURL := s.baseURL
	hc := s.hc
	s.mu.Unlock()

	if language == "" {
		language = s.cfg.Language
	}
	return analyzeOnce(ctx, hc, baseURL, text, language)
}

// Stop gracefully terminates the child (SIGTERM, then SIGKILL after
// 5s). Idempotent; safe to call from a defer even if Start failed.
//
// Stop returns nil unless the child was never started. We do not
// surface the child's exit error here: callers that care about
// post-mortem debugging should pass a Stderr in Config.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	cmd := s.cmd
	done := s.done
	hc := s.hc
	// Drop in-flight HTTP idle connections so an Analyze racing with
	// Stop sees a fast connection-refused rather than a hang.
	if hc != nil {
		hc.CloseIdleConnections()
	}
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	// Best-effort SIGTERM. On Windows os.Process.Signal(SIGTERM)
	// returns an error; Kill is the practical fallback. We don't
	// run on Windows for the server side anyway, but the code
	// stays portable.
	_ = cmd.Process.Signal(syscall.SIGTERM)

	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		// Grace window expired; escalate to SIGKILL. Kill returns
		// an error if the process is already gone; we don't care.
		_ = cmd.Process.Kill()
		<-done
		return nil
	}
}

// BaseURL returns the resolved http://host:port the supervisor is
// talking to. Empty before Start succeeds. Exposed for tests and
// for diagnostic logging in the engine layer.
func (s *Supervisor) BaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseURL
}

// isLoopback reports whether host is a literal loopback address.
// We accept the two IP literals plus "localhost"; anything else
// (including resolvable hostnames) is rejected because we cannot
// guarantee the resolution lands on a loopback interface.
func isLoopback(host string) bool {
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
