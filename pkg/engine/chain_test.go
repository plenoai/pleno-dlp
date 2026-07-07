package engine

import "testing"

// leakSink is a test double that records whether Close reached it, and
// forwards to inner like every real Sink implementation in this
// package does. Used to prove SinkChain.Close reaches every link
// regardless of how many buffering sinks sit in between — the
// invariant issue #282 asks for.
type leakSink struct {
	inner  Sink
	closed bool
}

func (l *leakSink) Emit(Finding) {}

func (l *leakSink) Close() error {
	l.closed = true
	if l.inner != nil {
		return l.inner.Close()
	}
	return nil
}

// bufferingLeakSink additionally buffers: Flush must be called before
// its buffered state is visible, mirroring gitCrossCommitSink and
// piidb.Sink. Close delegates to Flush like both of those do.
type bufferingLeakSink struct {
	leakSink
	flushed bool
}

func (b *bufferingLeakSink) Flush() error {
	b.flushed = true
	return nil
}

func (b *bufferingLeakSink) Close() error {
	if err := b.Flush(); err != nil {
		return err
	}
	b.leakSink.closed = true
	if b.inner != nil {
		return b.inner.Close()
	}
	return nil
}

func TestSinkChain_CloseReachesEveryLink(t *testing.T) {
	terminal := &leakSink{}
	chain := NewSinkChain()
	chain.Track(terminal)

	mid := &bufferingLeakSink{leakSink: leakSink{inner: terminal}}
	chain.Track(mid)

	outer := &leakSink{inner: mid}
	chain.Track(outer)

	if err := chain.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !outer.closed {
		t.Error("outer sink never closed — Close did not reach the outermost link")
	}
	if !mid.closed {
		t.Error("buffering middle sink never closed — Close did not propagate through it")
	}
	if !terminal.closed {
		t.Error("terminal sink never closed — Close did not reach the bottom of the chain")
	}
}

func TestSinkChain_CloseIsIdempotent(t *testing.T) {
	counting := &countingCloseSink{}
	chain := NewSinkChain()
	chain.Track(counting)

	if err := chain.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := chain.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if counting.closes != 1 {
		t.Errorf("underlying Close invoked %d times, want exactly 1", counting.closes)
	}
}

type countingCloseSink struct{ closes int }

func (c *countingCloseSink) Emit(Finding) {}
func (c *countingCloseSink) Close() error { c.closes++; return nil }

func TestSinkChain_FlushReachesEveryBufferingLinkWithoutClosing(t *testing.T) {
	terminal := &leakSink{}
	chain := NewSinkChain()
	chain.Track(terminal)

	mid1 := &bufferingLeakSink{leakSink: leakSink{inner: terminal}}
	chain.Track(mid1)

	passthrough := &leakSink{inner: mid1}
	chain.Track(passthrough)

	mid2 := &bufferingLeakSink{leakSink: leakSink{inner: passthrough}}
	chain.Track(mid2)

	if err := chain.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if !mid1.flushed {
		t.Error("inner buffering sink never flushed")
	}
	if !mid2.flushed {
		t.Error("outer buffering sink never flushed")
	}
	if terminal.closed || mid1.closed || passthrough.closed || mid2.closed {
		t.Error("Flush closed a link — Flush must forward buffered data without closing anything")
	}
}

func TestSinkChain_TrackReturnsArgumentUnchanged(t *testing.T) {
	chain := NewSinkChain()
	s := &leakSink{}
	got := chain.Track(s)
	if got != Sink(s) {
		t.Error("Track must return its argument unchanged so call sites can wrap construction in place")
	}
}

func TestSinkChain_EmptyChainCloseIsNoop(t *testing.T) {
	chain := NewSinkChain()
	if err := chain.Close(); err != nil {
		t.Fatalf("Close on empty chain: %v", err)
	}
	if err := chain.Flush(); err != nil {
		t.Fatalf("Flush on empty chain: %v", err)
	}
}
