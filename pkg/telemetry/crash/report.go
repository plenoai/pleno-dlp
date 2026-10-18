package crash

import (
	"encoding/json"
	"runtime"
	"time"
)

// Schema identifies the report wire format. Breaking shape changes bump the
// suffix; the relay rejects schemas it does not know.
const Schema = "pleno-dlp.crash/v1"

// MaxReportBytes bounds the marshalled report so a pathological stack cannot
// turn the relay into a bulk upload channel.
const MaxReportBytes = 32 << 10

// truncatedMarker terminates a stack that was cut to fit MaxReportBytes.
const truncatedMarker = "\n...[truncated]"

// Kind classifies how the crash was captured.
type Kind string

const (
	// KindPanic is an unrecovered panic observed by the supervisor.
	KindPanic Kind = "panic"
	// KindFatal is a runtime fatal error (e.g. concurrent map writes)
	// observed by the supervisor; these cannot be recovered in-process.
	KindFatal Kind = "fatal"
	// KindRecovered is a main-goroutine panic caught by Recover.
	KindRecovered Kind = "recovered"
)

// Report is the complete crash payload. Fields are an allowlist: anything
// not declared here is never collected.
type Report struct {
	Schema      string    `json:"schema"`
	Fingerprint string    `json:"fingerprint"`
	Version     string    `json:"version"`
	Commit      string    `json:"commit"`
	GOOS        string    `json:"goos"`
	GOARCH      string    `json:"goarch"`
	GoVersion   string    `json:"go_version"`
	Command     string    `json:"command"`
	Flags       []string  `json:"flags"`
	Kind        Kind      `json:"kind"`
	Message     string    `json:"message"`
	Stack       string    `json:"stack"`
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

// Build assembles a redacted, fingerprinted, size-bounded report.
func Build(kind Kind, message, stack string, meta Meta, red *Redactor, now time.Time) Report {
	msg := red.Redact(message)
	stk := red.Redact(stack)
	flags := meta.Flags
	if flags == nil {
		flags = []string{}
	}
	r := Report{
		Schema:      Schema,
		Fingerprint: Fingerprint(msg, stk),
		Version:     meta.Version,
		Commit:      meta.Commit,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		GoVersion:   runtime.Version(),
		Command:     red.Redact(meta.Command),
		Flags:       flags,
		Kind:        kind,
		Message:     msg,
		Stack:       stk,
		CreatedAt:   now.UTC().Truncate(time.Minute),
	}
	bound(&r)
	return r
}

// bound truncates the stack tail (then the message) until the marshalled
// report fits MaxReportBytes.
func bound(r *Report) {
	for {
		b, err := json.Marshal(r)
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
