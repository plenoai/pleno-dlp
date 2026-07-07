package engine

import "sync"

// Flushable is implemented by sinks that buffer findings and need an
// explicit mid-scan flush to forward buffered data downstream without
// closing the chain beneath them — e.g. cross-commit dedup and PII
// classification batching. Close must internally Flush before closing
// inner (both existing implementations already do), so Flush is always
// safe to call more than once and is never itself load-bearing for
// correctness on process exit — only for callers that need buffered
// findings visible before the chain closes.
type Flushable interface {
	Flush() error
}

// SinkChain tracks the sinks composed into one scan's Sink chain, in
// wrap order (terminal sink first, outermost last), and owns their
// lifecycle so wiring a new buffering sink into the chain can never
// silently drop its output again — the caller-owned Close/Flush wiring
// that caused issue #273 is centralized here instead of re-derived
// per scan command.
//
// Track must be called once per sink, in the same order the sinks wrap
// each other (each Track's argument wraps the previous one). Close and
// Flush then only ever need to be called on the chain, never on an
// individual link.
type SinkChain struct {
	flushables []Flushable
	outer      Sink
	closeOnce  sync.Once
	closeErr   error
}

// NewSinkChain returns an empty chain. Track the terminal sink first.
func NewSinkChain() *SinkChain {
	return &SinkChain{}
}

// Track registers s as the new outermost link and returns it unchanged,
// so call sites can wrap Track(...) around the existing sink
// construction expression without otherwise restructuring it. Sinks
// that implement Flushable are added to the flush list automatically —
// no per-type wiring at the call site.
func (c *SinkChain) Track(s Sink) Sink {
	if f, ok := s.(Flushable); ok {
		c.flushables = append(c.flushables, f)
	}
	c.outer = s
	return s
}

// Flush forwards every buffered finding in every Flushable link, outer
// to inner in track order, so a caller can read post-scan sink state
// (counters, classification results) before the chain closes. Safe to
// call zero or more times before Close.
func (c *SinkChain) Flush() error {
	for _, f := range c.flushables {
		if err := f.Flush(); err != nil {
			return err
		}
	}
	return nil
}

// Close closes the outermost tracked sink exactly once; every inner
// link closes via that sink's own Close() forwarding, which is the
// existing contract every Sink implementation in this codebase already
// follows. Calling Close more than once returns the first call's
// result without closing anything a second time — the outer→inner,
// exactly-once guarantee issue #282 asks for.
func (c *SinkChain) Close() error {
	c.closeOnce.Do(func() {
		if c.outer != nil {
			c.closeErr = c.outer.Close()
		}
	})
	return c.closeErr
}
