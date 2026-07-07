// Package engine (this file): IsPlaceholder recognises well-known
// documentation / template literals so they don't get reported as leaked
// secrets. Two independent matching strategies are combined, chosen
// per-marker by how safe a bare substring match is for that marker:
//
//  1. Template-scaffolding markers (templateSubstrings below —
//     "your_token", "your_key", "your_secret", "<token>", "<secret>",
//     "<key>") match anywhere in the value via bytes.Contains. These only
//     ever occur as deliberate scaffolding a human copy-pastes over
//     ("Bearer <TOKEN>", "sk_live_YOUR_SECRET_HERE") — a real secret
//     would never legitimately contain "<token>" or "your_secret" as a
//     substring, so Contains carries no over-suppression risk.
//
//  2. Word markers (wordMarkers below — "example", "placeholder",
//     "redacted") do NOT use Contains. A real credential can legitimately
//     contain "example" as a substring (a key scoped to example.com
//     infra, a generated password that happens to embed "Example") — see
//     issue #290, where FileZillaXML's correctly-extracted
//     "ExamplePas123" was silently dropped by the old Contains check.
//     Instead a word marker only trips IsPlaceholder when it dominates
//     the value's shape: split the (lower-cased) value into runs of
//     alphanumeric characters ("words", delimited by any non-alnum byte
//     or the string boundary) and require the marker words to account
//     for a strict majority — more than half — of the total alnum byte
//     count. "PLACEHOLDER" (100% marker) and "EXAMPLE_KEY" (70% marker)
//     trip it; "ExamplePas123" (no word boundary around "example" at
//     all — it's a fragment of one continuous run) and "Bearer REDACTED
//     here" (marker is 44% of the alnum content) do not.
//
// A small number of specific, publicly-documented literals (the AWS SDK
// docs' AKIAIOSFODNN7EXAMPLE access key id and its paired secret key) are
// exact-matched instead of relying on either heuristic above: "EXAMPLE"
// is a trailing fragment of one continuous alnum run there
// (AKIAIOSFODNN7EXAMPLE), so it does not qualify as a standalone word
// under rule 2, yet the literal is safe to always drop because it is a
// fixed, universally-repeated docs placeholder that cannot correspond to
// any real account.
//
// Runs of a single repeated character (X{8,}, 0{10,}) and a short list of
// exact single-token placeholders (dummy, test, foo, bar, password,
// changeme) are unaffected by any of the above — they were already
// exact/structural matches, not substring matches, so they carried no
// over-suppression risk to begin with.
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
	for _, marker := range templateSubstrings {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	if wordMarkerDominates(lower) {
		return true
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

// templateSubstrings match anywhere in the value (bytes.Contains) — see
// the package doc, strategy 1. These are deliberate template scaffolding
// that a real secret would never legitimately contain as a substring.
var templateSubstrings = [][]byte{
	[]byte("your_token"),
	[]byte("your_key"),
	[]byte("your_secret"),
	[]byte("<token>"),
	[]byte("<secret>"),
	[]byte("<key>"),
}

// wordMarkers must dominate the value's word shape to trip IsPlaceholder
// — see the package doc, strategy 2 and wordMarkerDominates.
var wordMarkers = [][]byte{
	[]byte("example"),
	[]byte("placeholder"),
	[]byte("redacted"),
}

// wordMarkerDominates reports whether lower's alphanumeric "words"
// (runs delimited by any non-alnum byte or the string boundary) are, by
// byte count, strictly more than half composed of wordMarkers entries.
// lower must already be lower-cased (callers pass the same buffer used
// for the Contains checks above, avoiding a second allocation).
func wordMarkerDominates(lower []byte) bool {
	total, matched := 0, 0
	tokenStart := -1
	flush := func(end int) {
		if tokenStart < 0 {
			return
		}
		tok := lower[tokenStart:end]
		total += len(tok)
		for _, m := range wordMarkers {
			if bytes.Equal(tok, m) {
				matched += len(tok)
				break
			}
		}
		tokenStart = -1
	}
	for i, b := range lower {
		if isAlnumASCII(b) {
			if tokenStart < 0 {
				tokenStart = i
			}
			continue
		}
		flush(i)
	}
	flush(len(lower))
	if total == 0 {
		return false
	}
	return matched*2 > total
}

func isAlnumASCII(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

var placeholderRunsRE = regexp.MustCompile(`(?i)X{8,}|0{10,}`)

// placeholderExactMatches are whole-value (case-insensitive) literal
// matches: short generic template tokens (dummy, test, foo, bar,
// password, changeme) plus a small set of specific, publicly-documented
// example credentials — see the package doc's closing paragraph for why
// these need an exact-literal path rather than the word-marker heuristic.
var placeholderExactMatches = [][]byte{
	[]byte("dummy"),
	[]byte("test"),
	[]byte("foo"),
	[]byte("bar"),
	[]byte("password"),
	[]byte("changeme"),
	// AWS SDK / CLI documentation's canonical example credential pair —
	// repeated verbatim across every AWS docs page and countless code
	// samples; not a fragment inside real key material (see package doc).
	[]byte("akiaiosfodnn7example"),
	[]byte("wjalrxutnfemi/k7mdeng/bpxrficyexamplekey"),
}

type placeholderSink struct {
	inner     Sink
	audit     Sink
	mu        sync.Mutex
	suppCount int64
}

// NewPlaceholderFilter wraps inner, dropping findings IsPlaceholder
// classifies as placeholder text. audit may be nil; when non-nil, every
// suppressed finding is also forwarded to audit with SuppressedBy set to
// "placeholder" (tagged, not silently dropped) instead of vanishing into
// only the aggregate stderr count — this is the --show-suppressed
// mechanism (issue #290). audit is typically the raw output sink so a
// suppressed finding still appears in --format json/table/sarif for
// auditing, without re-entering dedup/counting/--fail-on (audit.Emit is
// called directly, bypassing every sink downstream of this one in the
// normal chain).
func NewPlaceholderFilter(inner Sink, audit Sink) Sink {
	return &placeholderSink{inner: inner, audit: audit}
}

func (p *placeholderSink) Emit(f Finding) {
	if IsPlaceholder(f.Result.Raw) {
		p.mu.Lock()
		p.suppCount++
		p.mu.Unlock()
		if p.audit != nil {
			f.SuppressedBy = "placeholder"
			p.audit.Emit(f)
		}
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
