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

// TestSchemaContract_KindEnumMatches guards the one enumerated property:
// the schema's kind values must be exactly the Kind constants the client
// can emit, so the relay never sees a kind it cannot classify.
func TestSchemaContract_KindEnumMatches(t *testing.T) {
	doc := loadSchema(t)
	var kind struct {
		Enum []string `json:"enum"`
	}
	if err := json.Unmarshal(doc.Properties["kind"], &kind); err != nil {
		t.Fatalf("schema.properties.kind: %v", err)
	}
	got := append([]string(nil), kind.Enum...)
	sort.Strings(got)
	want := []string{string(KindFatal), string(KindPanic), string(KindRecovered)}
	sort.Strings(want)
	if !equalStrings(got, want) {
		t.Errorf("schema kind enum = %v, want %v (Kind constants)", got, want)
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
// fully-populated Report and one built by the runtime path, and checks
// the result against the published allowlist and required set, mirroring
// the relay's validate().
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

	created := time.Date(2026, 10, 18, 0, 41, 0, 0, time.UTC)
	full := Build(KindRecovered, "panic: x", "goroutine [running]:", Meta{Version: "v0.67.0", Commit: "abc123", Command: "scan filesystem", Flags: []string{"json"}}, &Redactor{}, created)
	assertReportShape(t, full, allowed, required)

	built := Build(KindPanic, "panic: index out of range", "goroutine [running]:", Meta{Version: "v0.67.0"}, &Redactor{}, created)
	assertReportShape(t, built, allowed, required)
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
	valid := Build(KindPanic, "panic: boom", "goroutine [running]:", Meta{Version: "v0.67.0", Flags: []string{"json"}}, &Redactor{}, time.Now())
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}

	tests := []struct {
		name    string
		mutate  func(*Report)
		wantErr bool
	}{
		{name: "wrong schema", mutate: func(r *Report) { r.Schema = "pleno-dlp.crash/v0" }, wantErr: true},
		{name: "empty schema", mutate: func(r *Report) { r.Schema = "" }, wantErr: true},
		{name: "optional fields blank", mutate: func(r *Report) { r.Commit, r.Stack = "", "" }},
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

// TestBuildSatisfiesSchema ties the runtime builder to the published
// contract so a field added to Build without the schema is caught here.
func TestBuildSatisfiesSchema(t *testing.T) {
	r := Build(KindRecovered, "panic: x", "goroutine 1 [running]:\nmain.main()\n", Meta{
		Version: "v0.67.0",
		Commit:  "abc",
		Command: "scan filesystem",
		Flags:   []string{"json", "quiet"},
	}, &Redactor{}, time.Now())
	if err := r.Validate(); err != nil {
		t.Fatalf("Build(...).Validate() = %v, want nil", err)
	}
	var m map[string]json.RawMessage
	b, _ := json.Marshal(r)
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if got, want := len(m), len(AllowedFields()); got != want {
		t.Fatalf("Build marshals %d fields, want %d: %v", got, want, sortedKeys(m))
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
