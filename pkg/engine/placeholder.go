package engine

import (
	"bytes"
	"regexp"
	"sync"
)

func IsPlaceholder(raw []byte) bool {
	if len(raw) == 0 {
		return false
	}
	lower := bytes.ToLower(raw)
	for _, marker := range placeholderSubstrings {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	if placeholderRunsRE.Match(raw) {
		return true
	}
	for _, exact := range placeholderExactMatches {
		if bytes.Equal(lower, exact) {
			return true
		}
	}
	return false
}

var placeholderSubstrings = [][]byte{
	[]byte("example"),
	[]byte("your_token"),
	[]byte("your_key"),
	[]byte("your_secret"),
	[]byte("placeholder"),
	[]byte("redacted"),
	[]byte("<token>"),
	[]byte("<secret>"),
	[]byte("<key>"),
}

var placeholderRunsRE = regexp.MustCompile(`(?i)X{8,}|0{10,}`)

var placeholderExactMatches = [][]byte{
	[]byte("dummy"),
	[]byte("test"),
	[]byte("foo"),
	[]byte("bar"),
	[]byte("password"),
	[]byte("changeme"),
}

type placeholderSink struct {
	inner     Sink
	mu        sync.Mutex
	suppCount int64
}

func NewPlaceholderFilter(inner Sink) Sink {
	return &placeholderSink{inner: inner}
}

func (p *placeholderSink) Emit(f Finding) {
	if IsPlaceholder(f.Result.Raw) {
		p.mu.Lock()
		p.suppCount++
		p.mu.Unlock()
		return
	}
	p.inner.Emit(f)
}

func (p *placeholderSink) Close() error { return p.inner.Close() }

// SuppressedCount returns how many findings the placeholder filter
// muted across the scan. Mirrors allowlistSink.SuppressedCount so the
// CLI can surface a "filtered N placeholder(s)" line on stderr the
// same way it does for the allowlist.
func (p *placeholderSink) SuppressedCount() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.suppCount
}

// PlaceholderSuppressedCounter is the public accessor — callers hold a
// Sink and want the count without knowing the concrete type. Returns
// -1 when sink is not a placeholderSink so future wrapping layers can
// distinguish "no placeholder filter installed" from "zero hits".
func PlaceholderSuppressedCounter(s Sink) int64 {
	if p, ok := s.(*placeholderSink); ok {
		return p.SuppressedCount()
	}
	return -1
}
