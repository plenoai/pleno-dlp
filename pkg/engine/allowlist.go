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

// Allowlist describes accepted findings.
type Allowlist struct {
	Entries []AllowlistEntry `json:"entries"`
}

// AllowlistEntry is one suppression rule.
type AllowlistEntry struct {
	Reason   string `json:"reason,omitempty"`
	Detector string `json:"detector,omitempty"`
	Raw      string `json:"raw,omitempty"`
	RawRegex string `json:"raw_regex,omitempty"`
	Path     string `json:"path,omitempty"`

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

// LoadAllowlistFile opens path and delegates to LoadAllowlist.
func LoadAllowlistFile(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("allowlist: open %s: %w", path, err)
	}
	defer f.Close()
	return LoadAllowlist(f)
}

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

// allowlistSink suppresses matched findings before they reach the inner sink.
type allowlistSink struct {
	inner     Sink
	allowlist *Allowlist
	audit     Sink
	mu        sync.Mutex
	suppCount int64
}

// NewAllowlist wraps inner and passes through when no rules are configured.
func NewAllowlist(allowlist *Allowlist, inner Sink) Sink {
	return NewAllowlistWithAudit(allowlist, inner, nil)
}

// NewAllowlistWithAudit is the audit-capable constructor: when audit is
// non-nil, every finding the allowlist matches is also forwarded to
// audit with SuppressedBy set to "allowlist" instead of only tallying
// it, the same mechanism placeholderSink uses for --show-suppressed
// (issue #290). No CLI flag wires audit through for the allowlist yet —
// this constructor exists purely as the extension point issue #290
// asks for; NewAllowlist's default (audit=nil) behaviour is unchanged.
func NewAllowlistWithAudit(allowlist *Allowlist, inner Sink, audit Sink) Sink {
	if allowlist == nil || len(allowlist.Entries) == 0 {
		return inner
	}
	return &allowlistSink{inner: inner, allowlist: allowlist, audit: audit}
}

func (a *allowlistSink) Emit(f Finding) {
	if a.allowlist.Match(f) {
		a.mu.Lock()
		a.suppCount++
		a.mu.Unlock()
		if a.audit != nil {
			f.SuppressedBy = "allowlist"
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

func SuppressedCounter(s Sink) int64 {
	if a, ok := s.(*allowlistSink); ok {
		return a.SuppressedCount()
	}
	return -1
}

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

// pathMatch matches against the full path and basename.
// `**` uses a lightweight ordered-fragment fallback.
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

// globContainsMatch is the lightweight `**` fallback.
func globContainsMatch(pattern, path string) bool {
	frags := strings.Split(pattern, "**")
	rest := filepath.ToSlash(path)
	for i, frag := range frags {
		if frag == "" {
			continue
		}
		frag = strings.Trim(frag, "/")
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
