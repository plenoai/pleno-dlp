package crash

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Schema identifies the report wire format. Breaking shape changes bump the
// suffix; the relay rejects schemas it does not know.
const Schema = "pleno-dlp.crash/v1"

// schemaJSON is the published JSON Schema for the report wire format. It is
// the single source of truth shared with the plenoai.com crash relay: the
// struct tags below and the vendored relay's allowlist are both asserted
// against it (pkg/telemetry/crash/report_test.go and
// workers/crash-relay/crash-relay.test.js), so a field added to either side
// without the schema fails CI.
//
//go:embed schema/pleno-dlp.crash.v1.json
var schemaJSON []byte

// SchemaJSON returns the published JSON Schema exactly as embedded in the
// binary. It is the same bytes the relay contract test reads from disk.
func SchemaJSON() []byte {
	out := make([]byte, len(schemaJSON))
	copy(out, schemaJSON)
	return out
}

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
// not declared here is never collected. Field order and the `crash` tags
// mirror the properties and required list in
// schema/pleno-dlp.crash.v1.json; every field is required (never omitempty)
// so a spooled report always carries the full contract.
type Report struct {
	Schema      string    `json:"schema" crash:"required"`
	Fingerprint string    `json:"fingerprint" crash:"required"`
	Version     string    `json:"version" crash:"required"`
	Commit      string    `json:"commit" crash:"required"`
	GOOS        string    `json:"goos" crash:"required"`
	GOARCH      string    `json:"goarch" crash:"required"`
	GoVersion   string    `json:"go_version" crash:"required"`
	Command     string    `json:"command" crash:"required"`
	Flags       []string  `json:"flags" crash:"required"`
	Kind        Kind      `json:"kind" crash:"required"`
	Message     string    `json:"message" crash:"required"`
	Stack       string    `json:"stack" crash:"required"`
	CreatedAt   time.Time `json:"created_at" crash:"required"`
}

// AllowedFields returns the sorted JSON property allowlist for a Report,
// derived from the struct tags so it cannot silently diverge from the
// marshaled shape. It is the Go half of the relay contract.
func AllowedFields() []string {
	return fieldsByTag("")
}

// RequiredFields returns the sorted JSON properties a Report must carry,
// derived from the `crash:"required"` struct tags.
func RequiredFields() []string {
	return fieldsByTag("required")
}

func fieldsByTag(want string) []string {
	t := reflect.TypeOf(Report{})
	fields := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		if want == "" || stringInList(f.Tag.Get("crash"), want) {
			fields = append(fields, name)
		}
	}
	sort.Strings(fields)
	return fields
}

func stringInList(list, want string) bool {
	for _, part := range strings.Split(list, ",") {
		if part == want {
			return true
		}
	}
	return false
}

// Validate reports whether r satisfies the pleno-dlp.crash/v1 contract: the
// schema identifier is exact, the marshaled object carries no property
// outside the allowlist, and every required property is present with the
// type the schema declares.
func (r Report) Validate() error {
	if r.Schema != Schema {
		return fmt.Errorf("crash: schema = %q, want %q", r.Schema, Schema)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("crash: marshal: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		return fmt.Errorf("crash: unmarshal: %w", err)
	}
	allowed := make(map[string]bool, len(AllowedFields()))
	for _, name := range AllowedFields() {
		allowed[name] = true
	}
	for name := range obj {
		if !allowed[name] {
			return fmt.Errorf("crash: field %q is not in the pleno-dlp.crash/v1 allowlist", name)
		}
	}
	for _, name := range RequiredFields() {
		raw, ok := obj[name]
		if !ok {
			return fmt.Errorf("crash: required field %q is missing", name)
		}
		if name == "flags" {
			var flags []string
			if err := json.Unmarshal(raw, &flags); err != nil {
				return fmt.Errorf("crash: field %q must be an array of strings: %w", name, err)
			}
			continue
		}
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("crash: field %q must be a string: %w", name, err)
		}
	}
	return nil
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
