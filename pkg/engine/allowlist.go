package engine

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Allowlist describes findings the user has explicitly accepted. Entries
// match by detector type (string form: "AWS", "GitHub", ...), by raw
// secret literal, by raw secret regex, or by path glob. Empty fields
// match anything in their dimension; an entry with all four empty is
// rejected at LoadAllowlist time so users can't accidentally mute every
// finding.
type Allowlist struct {
	Entries []AllowlistEntry `json:"entries"`
}

// AllowlistEntry is one rule. AND across the four matchers — every
// non-empty matcher must hit for the entry to suppress a finding.
// Reason is opaque to the engine and surfaces in --explain output to
// remind reviewers why this entry exists.
type AllowlistEntry struct {
	Reason   string `json:"reason,omitempty"`
	Detector string `json:"detector,omitempty"`
	Raw      string `json:"raw,omitempty"`
	RawRegex string `json:"raw_regex,omitempty"`
	Path     string `json:"path,omitempty"`

	rawRegexCompiled *regexp.Regexp `json:"-"`
}

// LoadAllowlist parses JSON from r. The JSON shape is `{"entries": [...]}`
// — choosing a wrapper object (vs a top-level array) leaves room to grow
// the allowlist without breaking the wire format. Returns a nil
// Allowlist on empty input so callers can pass it through unconditionally.
func LoadAllowlist(r io.Reader) (*Allowlist, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("allowlist: read: %w", err)
	}
	if len(data) == 0 {
		return nil, nil
	}
	var raw Allowlist
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("allowlist: invalid json: %w", err)
	}
	for i := range raw.Entries {
		e := &raw.Entries[i]
		if e.Detector == "" && e.Raw == "" && e.RawRegex == "" && e.Path == "" {
			return nil, fmt.Errorf("allowlist entry %d: at least one of detector / raw / raw_regex / path is required", i)
		}
		if e.RawRegex != "" {
			rx, err := regexp.Compile(e.RawRegex)
			if err != nil {
				return nil, fmt.Errorf("allowlist entry %d: invalid raw_regex %q: %w", i, e.RawRegex, err)
			}
			e.rawRegexCompiled = rx
		}
	}
	return &raw, nil
}

// LoadAllowlistFile is a thin wrapper that opens path and feeds it to
// LoadAllowlist. The CLI calls this when --allowlist is set.
func LoadAllowlistFile(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: open %s: %w", path, err)
	}
	defer f.Close()
	return LoadAllowlist(f)
}

// Match reports whether any entry suppresses f. Used by allowlistSink to
// filter the stream; exported so tests (and downstream embedders that
// build their own sink chains) can reuse the matching logic without
// reimplementing it.
func (a *Allowlist) Match(f Finding) bool {
	if a == nil {
		return false
	}
	det := f.Detector.String()
	raw := string(f.Result.Raw)
	path := findingPath(f)
	for _, e := range a.Entries {
		if e.Detector != "" && !strings.EqualFold(e.Detector, det) {
			continue
		}
		if e.Raw != "" && e.Raw != raw {
			continue
		}
		if e.rawRegexCompiled != nil && !e.rawRegexCompiled.MatchString(raw) {
			continue
		}
		if e.Path != "" {
			if !pathMatch(e.Path, path) {
				continue
			}
		}
		return true
	}
	return false
}

// allowlistSink suppresses findings the allowlist matches and forwards
// the rest. It must sit OUTSIDE dedup so suppressed entries don't poison
// the dedup map (a different finding at a similar location should still
// emit even if the prior allowlisted one would have populated the cache).
type allowlistSink struct {
	inner     Sink
	allowlist *Allowlist
	mu        sync.Mutex
	suppCount int64
}

// NewAllowlist wraps inner. nil allowlist degenerates to a pass-through
// so callers don't need to special-case "no allowlist configured".
func NewAllowlist(allowlist *Allowlist, inner Sink) Sink {
	if allowlist == nil || len(allowlist.Entries) == 0 {
		return inner
	}
	return &allowlistSink{inner: inner, allowlist: allowlist}
}

func (a *allowlistSink) Emit(f Finding) {
	if a.allowlist.Match(f) {
		a.mu.Lock()
		a.suppCount++
		a.mu.Unlock()
		return
	}
	a.inner.Emit(f)
}

func (a *allowlistSink) Close() error { return a.inner.Close() }

// SuppressedCount returns how many findings the allowlist muted. The CLI
// surfaces this so users can spot stale allowlist entries: any rule with
// zero hits across many runs is probably a candidate for removal.
func (a *allowlistSink) SuppressedCount() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.suppCount
}

// SuppressedCounter is the public accessor for callers that hold a Sink
// and want the count. Returns -1 when sink is not an allowlistSink so
// pass-through wrapping (no allowlist configured) reports cleanly.
func SuppressedCounter(s Sink) int64 {
	if a, ok := s.(*allowlistSink); ok {
		return a.SuppressedCount()
	}
	return -1
}

// findingPath returns a path-shaped string for path-glob matching.
// Mirrors the dedup logic so allowlist semantics line up with what the
// user sees in output (file paths for filesystem, "<repo>:<file>" for
// git, etc).
func findingPath(f Finding) string {
	if f.Chunk == nil {
		return ""
	}
	md := f.Chunk.SourceMetadata
	switch {
	case md.Filesystem != nil:
		return md.Filesystem.Path
	case md.Git != nil:
		return md.Git.File
	case md.GitHub != nil:
		return md.GitHub.File
	case md.S3 != nil:
		return md.S3.Key
	case md.GCS != nil:
		return md.GCS.Object
	case md.Slack != nil:
		return md.Slack.Channel
	case md.Stdin != nil:
		return md.Stdin.Label
	}
	return ""
}

// pathMatch implements glob matching against the basename and the full
// path so an entry like `path: "*_test.go"` matches via basename, while
// `path: "fixtures/*.env"` matches via the full string. Mirrors the
// filesystem source's exclusion semantics — users only need to learn one
// glob dialect across the tool.
//
// We deliberately use filepath.Match (no `**` recursion). When `**` is
// in the pattern, fall back to a substring-style match by stripping the
// `**` markers — sufficient for the common "match anywhere in this
// subtree" intent without pulling in a full doublestar dependency.
func pathMatch(pattern, path string) bool {
	if pattern == "" {
		return false
	}
	if strings.Contains(pattern, "**") {
		return globContainsMatch(pattern, path)
	}
	if ok, _ := filepath.Match(pattern, filepath.ToSlash(path)); ok {
		return true
	}
	if ok, _ := filepath.Match(pattern, filepath.Base(path)); ok {
		return true
	}
	return false
}

// globContainsMatch implements a degenerate `**` handler: split on `**`
// and require every fragment to appear in order in the path. Good
// enough for `fixtures/**/*.env` and similar; full doublestar semantics
// (across slash boundaries) would require a third-party lib we'd rather
// not pull in for one feature.
func globContainsMatch(pattern, path string) bool {
	frags := strings.Split(pattern, "**")
	rest := filepath.ToSlash(path)
	for i, frag := range frags {
		if frag == "" {
			continue
		}
		// Strip leading/trailing path separators that flank the **.
		frag = strings.Trim(frag, "/")
		// Final fragment may be a glob pattern (e.g. `*.env`); allow it
		// to match anywhere in the remaining suffix via filepath.Match
		// against each remaining path component.
		if i == len(frags)-1 && strings.ContainsAny(frag, "*?[") {
			for {
				if rest == "" {
					return false
				}
				if ok, _ := filepath.Match(frag, rest); ok {
					return true
				}
				if ok, _ := filepath.Match(frag, filepath.Base(rest)); ok {
					return true
				}
				idx := strings.IndexByte(rest, '/')
				if idx < 0 {
					return false
				}
				rest = rest[idx+1:]
			}
		}
		idx := strings.Index(rest, frag)
		if idx < 0 {
			return false
		}
		rest = rest[idx+len(frag):]
	}
	return true
}
