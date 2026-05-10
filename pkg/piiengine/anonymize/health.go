package anonymize

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// pollReady polls baseURL+/ready until it returns 200, ctx cancels,
// or deadline elapses. Returns nil on first success.
//
// We poll /ready (not /health) because pleno-anonymize lazy-loads
// spaCy + ja_ner_ja the first time the readiness probe is hit.
// /health responds 200 immediately even before models are loaded;
// returning from Start with /health green would race the first
// Analyze call against model load and fail in confusing ways.
//
// Backoff is a fixed 100ms tick, not exponential. The whole loop
// is bounded by ReadyTimeout (default 60s) so worst-case overhead
// is ~600 polls, each a single TCP connect to localhost — the cost
// is negligible compared to spaCy load itself.
func pollReady(ctx context.Context, hc *http.Client, baseURL string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)

	// Poll context inherits cancel from caller but adds a deadline.
	// We don't propagate the deadline into individual HTTP calls
	// (each readyOnce call uses its own short timeout via the
	// http.Client) so a hung request can't burn the entire budget
	// on one attempt.
	pollCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()

	// First attempt is immediate so a fast-loading engine returns
	// in well under the 100ms tick.
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
		case <-tick.C:
			if err := readyOnce(pollCtx, hc, baseURL); err == nil {
				return nil
			}
		}
	}
}

// readyOnce performs one /ready GET. Errors are intentionally swallowed
// at the call site (pollReady loops); they're returned here only so
// pollReady's first-attempt fast path can detect immediate success.
//
// We use a per-request timeout that is shorter than the polling
// interval would suggest, because a hung connection to a slow-binding
// child would otherwise waste 100ms of slack per tick.
func readyOnce(ctx context.Context, hc *http.Client, baseURL string) error {
	reqCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
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
