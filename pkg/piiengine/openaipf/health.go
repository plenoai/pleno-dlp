package openaipf

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// pollReady polls baseURL+/ready until it returns 200, ctx cancels,
// the child process exits, or deadline elapses. Returns nil on first
// success.
//
// We poll /ready (not /health) because the FastAPI wrapper flips
// /ready only after the opf model weights download from HuggingFace
// AND the first forward pass JIT-compiles kernels. /health responds
// 200 the instant uvicorn is listening, well before the model is
// usable; returning from Start with /health green would race the
// first Analyze call against multi-GB of weight loading and fail in
// confusing ways.
//
// childExited (when non-nil) lets the poll loop fail fast on a
// crashing child rather than waiting the full ReadyTimeout. The
// supervisor closes this channel in its cmd.Wait reaper goroutine,
// so a mis-spawned engine (wrong python, missing torch, OOM during
// model load) surfaces in milliseconds instead of after a 5-minute
// timeout. Pass nil only in tests that don't model child lifecycle.
//
// Backoff is a fixed 250ms tick. opf's cold path is dominated by HF
// download and GPU kernel JIT — both are seconds-to-minutes scale,
// so a slightly slower poll than anonymize's 100ms cuts wasted
// connection churn without materially delaying ready detection.
// Whole loop is bounded by ReadyTimeout (default 300s).
func pollReady(ctx context.Context, hc *http.Client, baseURL string, timeout time.Duration, childExited <-chan struct{}) error {
	if timeout <= 0 {
		timeout = DefaultReadyTimeout
	}
	deadline := time.Now().Add(timeout)

	// Poll context inherits cancel from caller but adds a deadline.
	// We don't propagate the deadline into individual HTTP calls
	// (each readyOnce call uses its own short timeout via the
	// http.Client) so a hung request can't burn the entire budget
	// on one attempt.
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()

	// First attempt is immediate so a warm-cache engine returns in
	// well under the 250ms tick.
	if err := readyOnce(pollCtx, hc, baseURL); err == nil {
		return nil
	}

	for {
		select {
		case <-pollCtx.Done():
			// Distinguish "scan cancelled" (caller's ctx) from
			// "ready timed out" (our deadline). The former should
			// surface as the caller's error so the engine wiring
			// layer treats it as scan-abort rather than startup
			// failure.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrReadyTimeout
		case <-childExitedChan(childExited):
			// Child process Wait returned before /ready ever did —
			// fail fast so callers see the real failure mode
			// (ModuleNotFoundError, port-bind error, OOM during
			// transformers import, …) inside of a tick instead of
			// after the full ReadyTimeout.
			return ErrEngineExited
		case <-tick.C:
			if err := readyOnce(pollCtx, hc, baseURL); err == nil {
				return nil
			}
		}
	}
}

// childExitedChan normalises the optional childExited parameter so
// pollReady's select doesn't need a runtime nil-check. A nil channel
// blocks forever in a select, which is exactly the no-op behavior
// we want for callers (mostly tests) that don't model child lifecycle.
func childExitedChan(c <-chan struct{}) <-chan struct{} {
	return c
}

// readyOnce performs one /ready GET. Errors are intentionally swallowed
// at the call site (pollReady loops); they're returned here only so
// pollReady's first-attempt fast path can detect immediate success.
//
// Per-request timeout is shorter than the polling interval to avoid
// burning slack on a hung connection — a slow-binding child should
// surface as a fast connection-refused, not a stalled GET.
func readyOnce(ctx context.Context, hc *http.Client, baseURL string) error {
	reqCtx, cancel := context.WithTimeout(ctx, 750*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, baseURL+"/ready", nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ready: status %d", resp.StatusCode)
	}
	return nil
}
