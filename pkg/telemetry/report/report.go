package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// Schema identifies the report wire format. Breaking shape changes bump the
// suffix; the relay rejects schemas it does not know.
const Schema = "pleno-dlp.report/v1"

// Size bounds. MaxReportBytes caps the marshalled report so the relay cannot
// become a bulk upload channel; the per-field caps keep one field from
// starving the others.
const (
	MaxReportBytes  = 32 << 10
	MaxMessageBytes = 2048
	MaxStackBytes   = 24 << 10
)

// truncatedMarker terminates a field that was cut to fit its bound.
const truncatedMarker = "\n...[truncated]"

// Kind classifies why a report exists.
type Kind string

const (
	// KindCrash is captured automatically and sent only after opt-in.
	KindCrash Kind = "crash"
	// KindFeedback is free-form text submitted with `pleno-dlp feedback`.
	KindFeedback Kind = "feedback"
	// KindFalsePositive names a detector that matched something benign.
	KindFalsePositive Kind = "false-positive"
)

// CrashKind classifies how a crash was captured; set only for KindCrash.
type CrashKind string

const (
	// CrashPanic is an unrecovered panic observed by the supervisor.
	CrashPanic CrashKind = "panic"
	// CrashFatal is a runtime fatal error (e.g. concurrent map writes)
	// observed by the supervisor; these cannot be recovered in-process.
	CrashFatal CrashKind = "fatal"
	// CrashRecovered is a main-goroutine panic caught in-process.
	CrashRecovered CrashKind = "recovered"
)

// Report is the complete payload. Fields are an allowlist: anything not
// declared here is never collected. Every key is always present; fields
// that do not apply to a kind are the empty string.
type Report struct {
	Schema      string    `json:"schema"`
	Kind        Kind      `json:"kind"`
	CrashKind   CrashKind `json:"crash_kind"`
	Fingerprint string    `json:"fingerprint"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	GoVersion   string    `json:"go_version"`
	Command     string    `json:"command"`
	Flags       []string  `json:"flags"`
	Message     string    `json:"message"`
	Stack       string    `json:"stack"`
	Detector    string    `json:"detector"`
	CreatedAt   time.Time `json:"created_at"`
}

// Meta is the build and invocation context a report is stamped with.
type Meta struct {
	Version string
	Commit  string
	// Command is the subcommand path words, e.g. "scan filesystem".
	Command string
	// Flags are flag names only, never values.
	Flags []string
}

// BuildCrash assembles a redacted, fingerprinted, size-bounded crash report.
func BuildCrash(ck CrashKind, message, stack string, meta Meta, red *Redactor, now time.Time) Report {
	r := base(KindCrash, meta, red, now)
	r.CrashKind = ck
	r.Message = red.Redact(message)
	r.Stack = red.Redact(stack)
	r.Fingerprint = Fingerprint(r.Message, r.Stack)
	bound(&r)
	return r
}

// BuildUser assembles a redacted, size-bounded feedback or false-positive
// report. detector must already be a registered Type name for
// KindFalsePositive and empty otherwise; the result is validated.
func BuildUser(kind Kind, message, detector string, meta Meta, red *Redactor, now time.Time) (Report, error) {
	r := base(kind, meta, red, now)
	r.Message = strings.TrimSpace(red.Redact(message))
	r.Detector = detector
	bound(&r)
	return r, r.Validate()
}

func base(kind Kind, meta Meta, red *Redactor, now time.Time) Report {
	flags := meta.Flags
	if flags == nil {
		flags = []string{}
	}
	return Report{
		Schema:    Schema,
		Kind:      kind,
		Version:   meta.Version,
		Commit:    meta.Commit,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		GoVersion: runtime.Version(),
		Command:   red.Redact(meta.Command),
		Flags:     flags,
		CreatedAt: now.UTC().Truncate(time.Minute),
	}
}

var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Validate enforces the per-kind field contract, so a hand-edited spool file
// cannot smuggle crash-only fields into a feedback report or vice versa.
func (r Report) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("schema %q, want %q", r.Schema, Schema)
	}
	if len(r.Message) > MaxMessageBytes || len(r.Stack) > MaxStackBytes {
		return fmt.Errorf("message or stack exceeds its size bound")
	}
	switch r.Kind {
	case KindCrash:
		switch r.CrashKind {
		case CrashPanic, CrashFatal, CrashRecovered:
		default:
			return fmt.Errorf("crash_kind %q: want panic, fatal, or recovered", r.CrashKind)
		}
		if !fingerprintRe.MatchString(r.Fingerprint) {
			return fmt.Errorf("crash fingerprint %q: want 16 lowercase hex characters", r.Fingerprint)
		}
		if r.Detector != "" {
			return fmt.Errorf("detector is only valid for kind %q", KindFalsePositive)
		}
		return nil
	case KindFeedback, KindFalsePositive:
	default:
		return fmt.Errorf("kind %q: want crash, feedback, or false-positive", r.Kind)
	}
	switch {
	case r.CrashKind != "" || r.Fingerprint != "" || r.Stack != "":
		return fmt.Errorf("crash_kind, fingerprint, and stack are only valid for kind %q", KindCrash)
	case r.Message == "":
		return fmt.Errorf("message is empty")
	case r.Kind == KindFalsePositive && r.Detector == "":
		return fmt.Errorf("kind %q requires a detector", KindFalsePositive)
	case r.Kind == KindFeedback && r.Detector != "":
		return fmt.Errorf("detector is only valid for kind %q", KindFalsePositive)
	}
	return nil
}

// Marshal is the canonical encoding: what is spooled, previewed, and sent
// are the same bytes.
func Marshal(r Report) ([]byte, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// bound applies the per-field caps, then truncates the stack tail (then the
// message) until the canonical encoding fits MaxReportBytes.
func bound(r *Report) {
	r.Message = capField(r.Message, MaxMessageBytes)
	r.Stack = capField(r.Stack, MaxStackBytes)
	for {
		b, err := Marshal(*r)
		if err != nil || len(b) <= MaxReportBytes {
			return
		}
		over := len(b) - MaxReportBytes + len(truncatedMarker) + 64
		switch {
		case len(r.Stack) > over:
			r.Stack = cutRunes(r.Stack, len(r.Stack)-over) + truncatedMarker
		case len(r.Message) > over:
			r.Stack = ""
			r.Message = cutRunes(r.Message, len(r.Message)-over) + truncatedMarker
		default:
			r.Stack, r.Message = "", truncatedMarker
			return
		}
	}
}

// capField truncates s so that s plus the marker fits n bytes.
func capField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return cutRunes(s, n-len(truncatedMarker)) + truncatedMarker
}

// cutRunes truncates s to at most n bytes without splitting a UTF-8 rune.
func cutRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if n >= len(s) {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
