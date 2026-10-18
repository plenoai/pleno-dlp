// Package crash defines the v1 crash-report wire contract shared by the
// pleno-dlp client and the plenoai.com crash relay.
//
// The client emits at most one Report per unhandled panic. The relay only
// accepts a report whose keys are exactly the allowlist published in
// schema/pleno-dlp.crash.v1.json and whose required keys are present;
// any extra key is rejected so a future client field cannot leak scanned
// content without the relay being updated in lockstep.
//
// schema/pleno-dlp.crash.v1.json is the single source of truth. The Go
// Report struct and the relay's validate() are asserted against it on
// both sides: report_test.go rejects struct <-> schema drift, and the
// vendored relay test under workers/crash-relay rejects
// validate() <-> schema drift.
package crash

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"
)

// Schema is the contract identifier embedded in every Report as "schema".
// The relay rejects any other value. Bump it only on a breaking change to
// the allowlist or field semantics; see docs/crash-telemetry-schema.md.
const Schema = "pleno-dlp.crash/v1"

//go:embed schema/pleno-dlp.crash.v1.json
var schemaJSON []byte

// SchemaJSON returns the published JSON Schema exactly as embedded in the
// binary. It is the same bytes the relay contract test reads from disk.
func SchemaJSON() []byte {
	out := make([]byte, len(schemaJSON))
	copy(out, schemaJSON)
	return out
}

// Report is one pleno-dlp.crash/v1 payload. Field order and the
// "crash" struct tags mirror the properties and required list in
// schema/pleno-dlp.crash.v1.json; a required field must never carry
// omitempty, or it could vanish from a marshaled report.
type Report struct {
	// Schema pins the payload to this allowlist. Always Schema.
	Schema string `json:"schema" crash:"required"`
	// ReportID is a random per-report identifier for log correlation.
	ReportID string `json:"report_id" crash:"required"`
	// Timestamp is when the crash was captured, RFC 3339 in UTC.
	Timestamp string `json:"timestamp" crash:"required"`
	// Version is the pleno-dlp build version.
	Version string `json:"version" crash:"required"`
	// Commit is the pleno-dlp build commit; omitted when unknown.
	Commit string `json:"commit,omitempty"`
	// GoVersion is runtime.Version().
	GoVersion string `json:"go_version" crash:"required"`
	// OS is runtime.GOOS.
	OS string `json:"os" crash:"required"`
	// Arch is runtime.GOARCH.
	Arch string `json:"arch" crash:"required"`
	// Command is the top-level subcommand that panicked.
	Command string `json:"command" crash:"required"`
	// ErrorType is the panic value's Go type.
	ErrorType string `json:"error_type" crash:"required"`
	// ErrorMessage is the redacted panic message. It must never contain
	// scanned file content or secret material.
	ErrorMessage string `json:"error_message" crash:"required"`
	// StackTrace is the redacted goroutine stack; omitted when unavailable.
	StackTrace string `json:"stack_trace,omitempty"`
	// InstallID is a stable, non-reversible installation identifier for
	// deduplication; omitted when telemetry is disabled.
	InstallID string `json:"install_id,omitempty"`
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

// Validate reports whether r can be accepted by the relay: the schema
// identifier is exact, every required property is a non-empty string,
// and the marshaled object carries no property outside the allowlist.
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
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("crash: field %q must be a string: %w", name, err)
		}
		if s == "" {
			return fmt.Errorf("crash: required field %q is empty", name)
		}
	}
	return nil
}

// New builds a Report with the schema identifier and capture time set and
// the environment fields filled from the caller (so this package stays
// testable and does not read globals). Callers fill ErrorType,
// ErrorMessage, and the optional fields; the message and stack must
// already be redacted.
func New(now time.Time, version, commit, goVersion, goos, goarch, command, reportID string) Report {
	return Report{
		Schema:    Schema,
		ReportID:  reportID,
		Timestamp: now.UTC().Format(time.RFC3339),
		Version:   version,
		Commit:    commit,
		GoVersion: goVersion,
		OS:        goos,
		Arch:      goarch,
		Command:   command,
	}
}
