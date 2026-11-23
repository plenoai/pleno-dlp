package connectors

import (
	"context"
	"errors"
	"sync"

	"github.com/plenoai/pleno-dlp/pkg/engine"
)

// coverageGaps collects per-item provider failures (auth, rate limit,
// non-2xx, truncated body, refused cross-origin fetch) so a connector can
// keep scanning the rest and still report the gap as engine.DegradedError
// for --fail-on-coverage, instead of a silent zero-finding result (#882).
// Safe for concurrent use by errgroup workers.
type coverageGaps struct {
	mu       sync.Mutex
	failures []engine.ScanFailure
}

func (g *coverageGaps) fail(source string, err error) {
	g.mu.Lock()
	g.failures = append(g.failures, engine.ScanFailure{Kind: engine.FailureSource, Source: source, Err: err})
	g.mu.Unlock()
}

// has reports whether source has a recorded failure.
func (g *coverageGaps) has(source string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range g.failures {
		if f.Source == source {
			return true
		}
	}
	return false
}

// err returns nil when no gap was recorded.
func (g *coverageGaps) err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.failures) == 0 {
		return nil
	}
	failures := append([]engine.ScanFailure(nil), g.failures...)
	return &engine.DegradedError{Total: len(failures), Counts: map[engine.FailureKind]int{engine.FailureSource: len(failures)}, Failures: failures}
}

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
