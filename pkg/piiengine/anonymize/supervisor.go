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

type Supervisor struct {
	cfg Config

	hc *http.Client

	mu      sync.Mutex
	cmd     *exec.Cmd
	port    int
	baseURL string
	started bool
	stopped bool
	done    chan struct{}
}

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

	go func() {
		_ = cmd.Wait()
		close(s.done)
	}()

	if err := pollReady(ctx, s.hc, s.baseURL, s.cfg.ReadyTimeout, s.done); err != nil {
		_ = s.Stop()
		return err
	}
	return nil
}

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
	if hc != nil {
		hc.CloseIdleConnections()
	}
	s.mu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)

	select {
	case <-done:
		return nil
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return nil
	}
}

func (s *Supervisor) BaseURL() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.baseURL
}

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
