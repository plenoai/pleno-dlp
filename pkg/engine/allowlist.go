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

// Allowlist is the single suppression policy applied after dedup and the
// placeholder filter. It unifies four sources of accepted findings so every
// caller gets one counter, one audit path, and one ordering (issue #812):
//
//   - Entries: user-curated rules from .pleno-allow.json, --skip-regex, and
//     --skip-word;
//   - baseline fingerprints loaded with --baseline (see baseline.go);
//   - inline pragmas (`pleno-dlp:allow`) detected by the engine and carried
//     on Finding.InlineAllowed, honored when HonorInline is set.
type Allowlist struct {
	Entries []AllowlistEntry `json:"entries"`
	// HonorInline suppresses findings the engine marked InlineAllowed.
	// The CLI enables it unless --no-inline-allow is given.
	HonorInline bool `json:"-"`

	fingerprints map[string]struct{}
}

// Suppression reasons recorded in Finding.SuppressedBy and the per-reason
// counters.
const (
	SuppressedByAllowlist = "allowlist"
	SuppressedByBaseline  = "baseline"
	SuppressedByInline    = "inline-allow"
)

// AllowlistEntry is one suppression rule.
type AllowlistEntry struct {
	Reason   string `json:"reason,omitempty"`
	Detector string `json:"detector,omitempty"`
	Raw      string `json:"raw,omitempty"`
	RawRegex string `json:"raw_regex,omitempty"`
	Path     string `json:"path,omitempty"`
	// RawContains matches when Raw contains the value, case-insensitively
	// (the --skip-word form).
	RawContains string `json:"raw_contains,omitempty"`
	// Fingerprint matches Fingerprint(f) exactly.
	Fingerprint string `json:"fingerprint,omitempty"`

	rawRegexCompiled *regexp.Regexp `json:"-"`
}

// LoadAllowlist parses `{"entries":[...]}`. Empty input returns nil.
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
	entries := raw.Entries
	raw.Entries = nil
	if err := raw.Add(entries...); err != nil {
		return nil, err
	}
	return &raw, nil
}

// Add validates and appends entries. Entries that carry only a fingerprint
// are indexed so a large baseline stays O(1) per finding.
func (a *Allowlist) Add(entries ...AllowlistEntry) error {
	for i, e := range entries {
		if e.Detector == "" && e.Raw == "" && e.RawRegex == "" && e.Path == "" && e.RawContains == "" && e.Fingerprint == "" {
			return fmt.Errorf("allowlist entry %d: at least one of detector / raw / raw_regex / raw_contains / path / fingerprint is required", len(a.Entries)+i)
		}
		if e.RawRegex != "" {
			rx, err := regexp.Compile(e.RawRegex)
			if err != nil {
				return fmt.Errorf("allowlist entry %d: invalid raw_regex %q: %w", len(a.Entries)+i, e.RawRegex, err)
			}
			e.rawRegexCompiled = rx
		}
		if e.Fingerprint != "" && e.Detector == "" && e.Raw == "" && e.RawRegex == "" && e.Path == "" && e.RawContains == "" {
			if a.fingerprints == nil {
				a.fingerprints = map[string]struct{}{}
			}
			a.fingerprints[e.Fingerprint] = struct{}{}
			continue
		}
		a.Entries = append(a.Entries, e)
	}
	return nil
}

// AddFingerprints indexes baseline fingerprints.
func (a *Allowlist) AddFingerprints(fps ...string) {
	if a.fingerprints == nil {
		a.fingerprints = make(map[string]struct{}, len(fps))
	}
	for _, fp := range fps {
		if fp != "" {
			a.fingerprints[fp] = struct{}{}
		}
	}
}

func (a *Allowlist) active() bool {
	return a != nil && (len(a.Entries) > 0 || len(a.fingerprints) > 0 || a.HonorInline)
}

// LoadAllowlistFile opens path and delegates to LoadAllowlist.
func LoadAllowlistFile(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: open %s: %w", path, err)
	}
	defer f.Close()
	return LoadAllowlist(f)
}

// Match reports whether any configured rule suppresses f.
func (a *Allowlist) Match(f Finding) bool {
	return a.MatchReason(f) != ""
}

// MatchReason returns the suppression reason for f, or "" when f is kept.
// Inline pragmas win over baseline fingerprints, which win over entries, so
// the recorded reason names the most specific mechanism.
func (a *Allowlist) MatchReason(f Finding) string {
	if a == nil {
		return ""
	}
	if a.HonorInline && f.InlineAllowed {
		return SuppressedByInline
	}
	var fp string
	if len(a.fingerprints) > 0 {
		fp = Fingerprint(f)
		if _, ok := a.fingerprints[fp]; ok {
			return SuppressedByBaseline
		}
	}
	det := f.Detector.String()
	raw := string(f.Result.Raw)
	path := findingPath(f)
	for _, e := range a.Entries {
		if e.Fingerprint != "" {
			if fp == "" {
				fp = Fingerprint(f)
			}
			if e.Fingerprint != fp {
				continue
			}
		}
		if e.RawContains != "" && !strings.Contains(strings.ToLower(raw), strings.ToLower(e.RawContains)) {
			continue
		}
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
		return SuppressedByAllowlist
	}
	return ""
}

// allowlistSink suppresses matched findings before they reach the inner sink.
type allowlistSink struct {
	inner     Sink
	allowlist *Allowlist
	audit     Sink
	mu        sync.Mutex
	suppCount int64
	byReason  map[string]int64
}

// NewAllowlist wraps inner and passes through when no rules are configured.
func NewAllowlist(allowlist *Allowlist, inner Sink) Sink {
	return NewAllowlistWithAudit(allowlist, inner, nil)
}

// NewAllowlistWithAudit is the audit-capable constructor: when audit is
// non-nil, every finding the allowlist matches is also forwarded to
// audit with SuppressedBy set to the matching reason (allowlist,
// baseline, inline-allow) instead of only tallying it, the same mechanism
// placeholderSink uses for --show-suppressed (issues #290, #812). The CLI
// passes its --show-suppressed sink here; NewAllowlist keeps audit=nil.
func NewAllowlistWithAudit(allowlist *Allowlist, inner Sink, audit Sink) Sink {
	if !allowlist.active() {
		return inner
	}
	return &allowlistSink{inner: inner, allowlist: allowlist, audit: audit}
}

func (a *allowlistSink) Emit(f Finding) {
	if reason := a.allowlist.MatchReason(f); reason != "" {
		a.mu.Lock()
		a.suppCount++
		if a.byReason == nil {
			a.byReason = map[string]int64{}
		}
		a.byReason[reason]++
		a.mu.Unlock()
		if a.audit != nil {
			f.SuppressedBy = reason
			a.audit.Emit(f)
		}
		return
	}
	a.inner.Emit(f)
}

func (a *allowlistSink) Close() error { return a.inner.Close() }

func (a *allowlistSink) SuppressedCount() int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.suppCount
}

// SuppressedByReason returns per-reason suppression counts for an allowlist
// sink, or nil for any other sink.
func SuppressedByReason(s Sink) map[string]int64 {
	a, ok := s.(*allowlistSink)
	if !ok {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make(map[string]int64, len(a.byReason))
	for k, v := range a.byReason {
		out[k] = v
	}
	return out
}

func SuppressedCounter(s Sink) int64 {
	if a, ok := s.(*allowlistSink); ok {
		return a.SuppressedCount()
	}
	return -1
}

// FindingPath returns the path-like location used for allowlist path rules
// and fingerprints.
func FindingPath(f Finding) string { return findingPath(f) }

// findingPath returns the path-like field used for path matching.
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
	case md.AzureBlob != nil:
		return md.AzureBlob.Blob
	case md.Slack != nil:
		return md.Slack.Channel
	case md.GitLab != nil:
		return md.GitLab.Path
	case md.Confluence != nil:
		return md.Confluence.SpaceKey + "/" + md.Confluence.Title
	case md.Jira != nil:
		return md.Jira.Project + "/" + md.Jira.IssueKey
	case md.Notion != nil:
		return md.Notion.Title
	case md.Bitbucket != nil:
		return md.Bitbucket.Workspace + "/" + md.Bitbucket.Repo + "/" + md.Bitbucket.Path
	case md.Stdin != nil:
		return md.Stdin.Label
	}
	return ""
}

// pathMatch matches pattern against the full path and, for `**`-free
// patterns, the basename. `**` is handled by globContainsMatch.
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

// globContainsMatch reports whether pattern, which contains at least one `**`,
// matches path. `**` matches zero or more whole path segments rather than an
// arbitrary substring, so a literal fragment can never align with part of a
// segment: `test/**` matches `test/a/b.env` but not `latest/prod.env` or
// `src/contest.go`, and `**/vendor/**` matches `vendor/x.go` and
// `a/vendor/x.go` but not `src/notvendor/x/key.go`.
//
// Like the `**`-free branch, the match is not anchored to the start of the
// path: the pattern may begin at any segment boundary, which keeps the
// documented `fixtures/**/*.env` entry matching `repo/fixtures/sub/secret.env`.
// Every literal pattern segment must still align with a complete path segment.
func globContainsMatch(pattern, path string) bool {
	pattern = strings.Trim(filepath.ToSlash(pattern), "/")
	path = strings.Trim(filepath.ToSlash(path), "/")
	if pattern == "" {
		return path == ""
	}
	pSegs := strings.Split(pattern, "/")
	pathSegs := strings.Split(path, "/")
	for i := 0; i <= len(pathSegs); i++ {
		if matchSegments(pSegs, pathSegs[i:]) {
			return true
		}
	}
	return false
}

// matchSegments matches pattern segments against name segments. A `**` segment
// matches zero or more whole name segments; any other segment is matched with
// filepath.Match, which keeps `*`, `?` and character classes scoped to a single
// path segment.
func matchSegments(pattern, name []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			pattern = pattern[1:]
			for len(pattern) > 0 && pattern[0] == "**" {
				pattern = pattern[1:]
			}
			if len(pattern) == 0 {
				return true
			}
			for i := 0; i <= len(name); i++ {
				if matchSegments(pattern, name[i:]) {
					return true
				}
			}
			return false
		}
		if len(name) == 0 {
			return false
		}
		ok, err := filepath.Match(pattern[0], name[0])
		if err != nil || !ok {
			return false
		}
		pattern = pattern[1:]
		name = name[1:]
	}
	return len(name) == 0
}
