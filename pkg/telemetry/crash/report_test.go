package crash

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// schemaDocument is the subset of JSON Schema this package relies on.
// Tests parse the published file through the same bytes the binary
// embeds, so the file and the runtime contract can never diverge.
type schemaDocument struct {
	ID                   string                     `json:"$id"`
	Type                 string                     `json:"type"`
	AdditionalProperties *bool                      `json:"additionalProperties"`
	Required             []string                   `json:"required"`
	Properties           map[string]json.RawMessage `json:"properties"`
}

func loadSchema(t *testing.T) schemaDocument {
	t.Helper()
	var doc schemaDocument
	if err := json.Unmarshal(SchemaJSON(), &doc); err != nil {
		t.Fatalf("unmarshal embedded schema: %v", err)
	}
	return doc
}

// TestSchemaContract_StructMatchesPublishedSchema is the client half of
// the plenoai.com relay contract: every Report JSON property and every
// required property must match schema/pleno-dlp.crash.v1.json exactly. A
// field added to one without the other fails here.
func TestSchemaContract_StructMatchesPublishedSchema(t *testing.T) {
	doc := loadSchema(t)

	if doc.ID != Schema {
		t.Errorf("schema $id = %q, want %q", doc.ID, Schema)
	}
	if doc.Type != "object" {
		t.Errorf("schema type = %q, want %q", doc.Type, "object")
	}
	if doc.AdditionalProperties == nil || *doc.AdditionalProperties {
		t.Error("schema must set additionalProperties=false so the relay allowlist is closed")
	}

	if got, want := sortedKeys(doc.Properties), AllowedFields(); !equalStrings(got, want) {
		t.Errorf("schema properties = %v, want %v (Report struct tags)", got, want)
	}

	gotRequired := append([]string(nil), doc.Required...)
	sort.Strings(gotRequired)
	if want := RequiredFields(); !equalStrings(gotRequired, want) {
		t.Errorf("schema required = %v, want %v (Report crash:\"required\" tags)", gotRequired, want)
	}

	var meta struct {
		Const string `json:"const"`
	}
	if err := json.Unmarshal(doc.Properties["schema"], &meta); err != nil {
		t.Fatalf("schema.properties.schema: %v", err)
	}
	if meta.Const != Schema {
		t.Errorf("schema.properties.schema.const = %q, want %q", meta.Const, Schema)
	}
}

// TestSchemaContract_RequiredFieldsAreNeverOmitted guards the one way a
// struct change can silently break the required contract: marking a
// required property omitempty.
func TestSchemaContract_RequiredFieldsAreNeverOmitted(t *testing.T) {
	rt := reflect.TypeOf(Report{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		name, opts, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			t.Fatalf("Report field %s has no JSON name", f.Name)
		}
		if stringInList(f.Tag.Get("crash"), "required") && stringInList(opts, "omitempty") {
			t.Errorf("required field %q must not be omitempty", name)
		}
	}
}

// TestSchemaContract_MarshaledReportStaysWithinAllowlist marshals a
// fully-populated and a minimal Report and checks the result against the
// published allowlist, mirroring the relay's validate().
func TestSchemaContract_MarshaledReportStaysWithinAllowlist(t *testing.T) {
	doc := loadSchema(t)
	allowed := make(map[string]bool, len(doc.Properties))
	for _, k := range sortedKeys(doc.Properties) {
		allowed[k] = true
	}
	required := make(map[string]bool, len(doc.Required))
	for _, k := range doc.Required {
		required[k] = true
	}

	full := Report{
		Schema:       Schema,
		ReportID:     "r-1",
		Timestamp:    "2026-10-18T00:00:00Z",
		Version:      "v0.65.0",
		Commit:       "abc123",
		GoVersion:    "go1.26.9",
		OS:           "linux",
		Arch:         "amd64",
		Command:      "scan",
		ErrorType:    "string",
		ErrorMessage: "boom",
		StackTrace:   "goroutine 1 [running]:",
		InstallID:    "deadbeef",
	}
	assertReportShape(t, full, allowed, required)

	minimal := full
	minimal.Commit, minimal.StackTrace, minimal.InstallID = "", "", ""
	assertReportShape(t, minimal, allowed, required)
}

func assertReportShape(t *testing.T, r Report, allowed, required map[string]bool) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal Report: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatalf("unmarshal Report: %v", err)
	}
	for k := range obj {
		if !allowed[k] {
			t.Errorf("marshaled report carries non-allowlisted field %q", k)
		}
	}
	for k := range required {
		if _, ok := obj[k]; !ok {
			t.Errorf("marshaled report is missing required field %q", k)
		}
	}
}

func TestValidate(t *testing.T) {
	valid := Report{
		Schema:       Schema,
		ReportID:     "r-1",
		Timestamp:    "2026-10-18T00:00:00Z",
		Version:      "v0.65.0",
		GoVersion:    "go1.26.9",
		OS:           "linux",
		Arch:         "amd64",
		Command:      "scan",
		ErrorType:    "string",
		ErrorMessage: "boom",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Report)
		wantErr bool
	}{
		{name: "wrong schema", mutate: func(r *Report) { r.Schema = "pleno-dlp.crash/v0" }, wantErr: true},
		{name: "empty report_id", mutate: func(r *Report) { r.ReportID = "" }, wantErr: true},
		{name: "empty error_message", mutate: func(r *Report) { r.ErrorMessage = "" }, wantErr: true},
		{name: "optional fields blank", mutate: func(r *Report) { r.Commit, r.StackTrace, r.InstallID = "", "", "" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := valid
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}

func TestNew(t *testing.T) {
	now := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	r := New(now, "v0.65.0", "abc123", "go1.26.9", "linux", "amd64", "scan", "r-1")
	if r.Schema != Schema {
		t.Errorf("Schema = %q, want %q", r.Schema, Schema)
	}
	if r.Timestamp != "2026-10-18T01:02:03Z" {
		t.Errorf("Timestamp = %q, want RFC3339 UTC", r.Timestamp)
	}
	r.ErrorType = "string"
	r.ErrorMessage = "boom"
	if err := r.Validate(); err != nil {
		t.Errorf("New(...).Validate() = %v, want nil", err)
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
