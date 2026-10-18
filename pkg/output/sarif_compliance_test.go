package output

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	"github.com/plenoai/pleno-dlp/pkg/engine"
	"github.com/plenoai/pleno-dlp/pkg/sources"
)

// TestSARIF_GitHubCodeScanning_RequiredFields enforces every requirement
// the GitHub Code Scanning ingest hands back as `Validation error: ...`
// today. The source of truth is GitHub's docs, but exercising it here in
// CI prevents a quiet regression where we strip a field and downstream
// uploads start silently 422-ing.
func TestSARIF_GitHubCodeScanning_RequiredFields(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")
	s.Emit(sample())
	s.Emit(sample()) // emit twice to verify rule list dedups
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	must(t, doc["$schema"] != nil, "$schema is required")
	must(t, doc["version"] == "2.1.0", "version must be 2.1.0; got %v", doc["version"])

	runs := mustList(t, doc["runs"], "runs")
	must(t, len(runs) == 1, "expected exactly one run; got %d", len(runs))
	run := mustMap(t, runs[0], "run")

	tool := mustMap(t, run["tool"], "tool")
	driver := mustMap(t, tool["driver"], "tool.driver")
	must(t, driver["name"] == "pleno-dlp", "driver.name; got %v", driver["name"])
	must(t, driver["semanticVersion"] != nil, "driver.semanticVersion required")

	rules := mustList(t, driver["rules"], "driver.rules")
	must(t, len(rules) == 1, "expected one rule (deduped); got %d", len(rules))
	rule := mustMap(t, rules[0], "rule")
	must(t, rule["id"] == "AWS", "rule.id; got %v", rule["id"])
	must(t, mustMap(t, rule["shortDescription"], "rule.shortDescription")["text"] != nil,
		"rule.shortDescription.text required")
	must(t, mustMap(t, rule["defaultConfiguration"], "rule.defaultConfiguration")["level"] != nil,
		"rule.defaultConfiguration.level required")

	results := mustList(t, run["results"], "results")
	must(t, len(results) == 2, "expected 2 results; got %d", len(results))
	for i, raw := range results {
		r := mustMap(t, raw, "result")
		must(t, r["ruleId"] == "AWS", "results[%d].ruleId; got %v", i, r["ruleId"])
		must(t, r["level"] != nil, "results[%d].level required", i)
		fps := mustMap(t, r["partialFingerprints"], "result.partialFingerprints")
		must(t, fps["secret/v1"] != nil, "results[%d].partialFingerprints[secret/v1] required", i)
	}
}

// TestSARIF_RuleIDsMatchDeclaredRules guarantees every result.ruleId is
// declared in tool.driver.rules. GitHub Code Scanning rejects orphan
// ruleIds with `unknown rule reference` and quietly drops the upload —
// catastrophic in CI because the build still passes.
func TestSARIF_RuleIDsMatchDeclaredRules(t *testing.T) {
	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")

	// Three findings, two distinct detectors. We expect 2 rule
	// descriptors and 3 results, all referencing one of the 2 ids.
	s.Emit(sample())
	s.Emit(findingFor(detectors.GitHub, "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"))
	s.Emit(sample())
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	run := doc["runs"].([]any)[0].(map[string]any)

	declared := map[string]bool{}
	for _, r := range run["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any) {
		declared[r.(map[string]any)["id"].(string)] = true
	}
	for _, res := range run["results"].([]any) {
		id := res.(map[string]any)["ruleId"].(string)
		if !declared[id] {
			t.Fatalf("result references undeclared ruleId %q (declared: %v)", id, declared)
		}
	}
}

// TestSARIF_StableOrdering asserts the rule list ordering is deterministic
// across runs. Tools downstream (e.g. `sarif-multitool merge`) hash the
// SARIF document; non-determinism breaks their cache and creates flaky
// PR comments.
func TestSARIF_StableOrdering(t *testing.T) {
	var first, second bytes.Buffer

	for _, buf := range []*bytes.Buffer{&first, &second} {
		s, _ := NewSink("sarif", buf, "test")
		s.Emit(findingFor(detectors.SlackBotToken, "xoxb-1"))
		s.Emit(findingFor(detectors.AWS, "AKIA0000000000000000"))
		s.Emit(findingFor(detectors.GitHub, "ghp_1"))
		_ = s.Close()
	}
	// Allow result ordering to vary (it follows Emit order which is
	// implementation-defined under concurrent calls), but rules must
	// appear in the same order both times.
	rulesFirst := extractRuleIDs(t, first.Bytes())
	rulesSecond := extractRuleIDs(t, second.Bytes())
	if strings.Join(rulesFirst, ",") != strings.Join(rulesSecond, ",") {
		t.Fatalf("rule ordering not deterministic:\n  first:  %v\n  second: %v", rulesFirst, rulesSecond)
	}
}

// TestSARIF_SeverityDrivesLevel encodes the level mapping policy:
// Critical/High → "error" (block CI), Medium → "warning" (surface
// without blocking), Low/Info/Unknown → "note". Changing this policy
// without updating consumers would silently flip CI gating semantics.
func TestSARIF_SeverityDrivesLevel(t *testing.T) {
	cases := []struct {
		name string
		sev  detectors.Severity
		want string
	}{
		{"critical", detectors.SeverityCritical, "error"},
		{"high", detectors.SeverityHigh, "error"},
		{"medium", detectors.SeverityMedium, "warning"},
		{"low", detectors.SeverityLow, "note"},
		{"info", detectors.SeverityInfo, "note"},
		{"unknown defaults to note", detectors.SeverityUnknown, "note"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			s, _ := NewSink("sarif", &buf, "test")
			f := sample()
			f.Result.Severity = tc.sev
			s.Emit(f)
			_ = s.Close()
			var doc map[string]any
			_ = json.Unmarshal(buf.Bytes(), &doc)
			results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
			got := results[0].(map[string]any)["level"]
			if got != tc.want {
				t.Fatalf("level = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestSARIF_FingerprintIsContentBased verifies that two findings of the
// same secret in different files share their secret/v1 fingerprint —
// that's what makes GitHub dedup the same leak across rename / move.
func TestSARIF_FingerprintIsContentBased(t *testing.T) {
	akia := "AKIAIOSFODNN7EXAMPLE"
	mk := func(path string) engine.Finding {
		return engine.Finding{
			Detector: detectors.AWS,
			Result:   detectors.Result{DetectorType: detectors.AWS, Raw: []byte(akia)},
			Chunk: &sources.Chunk{
				SourceMetadata: sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: path, Line: 1}},
			},
		}
	}
	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")
	s.Emit(mk("/old/leak.txt"))
	s.Emit(mk("/new/leak.txt"))
	_ = s.Close()
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	a := results[0].(map[string]any)["partialFingerprints"].(map[string]any)["secret/v1"]
	b := results[1].(map[string]any)["partialFingerprints"].(map[string]any)["secret/v1"]
	if a != b {
		t.Fatalf("secret/v1 fingerprint should match across paths; got %v vs %v", a, b)
	}
	la := results[0].(map[string]any)["partialFingerprints"].(map[string]any)["location/v1"]
	lb := results[1].(map[string]any)["partialFingerprints"].(map[string]any)["location/v1"]
	if la == lb {
		t.Fatalf("location/v1 must differ across paths; both = %v", la)
	}
}

// findingFor builds a Finding for an arbitrary detector + redacted
// secret. Centralised so individual tests stay focused on the assertion
// rather than fixture setup.
func findingFor(det detectors.DetectorType, raw string) engine.Finding {
	return engine.Finding{
		Detector: det,
		Result: detectors.Result{
			DetectorType: det,
			Raw:          []byte(raw),
		},
		Chunk: &sources.Chunk{
			SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{Path: "/x.txt", Line: 1},
			},
		},
	}
}

// TestSARIF_ArtifactLocationURIEncoded pins that artifactLocation.uri is a
// valid RFC 3986 URI-reference even when a path or object key contains the
// characters that break an unencoded reference: space (illegal), `#`
// (fragment delimiter), `%` (invalid percent-escape), and `?` (query
// delimiter). Regression test for raw OS paths being emitted verbatim.
func TestSARIF_ArtifactLocationURIEncoded(t *testing.T) {
	const trickyRel = "a b/x#1%.env?tab=1"
	const trickyAbs = "/tmp/sx/a b/x#1%.env?tab=1"

	cases := []struct {
		name     string
		md       sources.Metadata
		want     string
		wantPath string
	}{
		{
			name:     "filesystem absolute becomes file URL",
			md:       sources.Metadata{Filesystem: &sources.FilesystemMeta{Path: trickyAbs, Line: 7}},
			want:     "file:///tmp/sx/a%20b/x%231%25.env%3Ftab=1",
			wantPath: trickyAbs,
		},
		{
			name:     "git repo-relative path",
			md:       sources.Metadata{Git: &sources.GitMeta{File: trickyRel, Line: 3}},
			want:     "a%20b/x%231%25.env%3Ftab=1",
			wantPath: trickyRel,
		},
		{
			name:     "github path",
			md:       sources.Metadata{GitHub: &sources.GitHubMeta{File: trickyRel, Line: 4}},
			want:     "a%20b/x%231%25.env%3Ftab=1",
			wantPath: trickyRel,
		},
		{
			name:     "s3 key",
			md:       sources.Metadata{S3: &sources.S3Meta{Bucket: "my bucket", Key: trickyRel}},
			want:     "s3://my%20bucket/a%20b/x%231%25.env%3Ftab=1",
			wantPath: trickyRel,
		},
		{
			name:     "gcs object",
			md:       sources.Metadata{GCS: &sources.GCSMeta{Bucket: "my bucket", Object: trickyRel}},
			want:     "gs://my%20bucket/a%20b/x%231%25.env%3Ftab=1",
			wantPath: trickyRel,
		},
		{
			name:     "sqldump file",
			md:       sources.Metadata{SQLDump: &sources.SQLDumpMeta{File: "/dumps/a b/x#1%.sql?x=1", Line: 9}},
			want:     "/dumps/a%20b/x%231%25.sql%3Fx=1",
			wantPath: "/dumps/a b/x#1%.sql?x=1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := sourceURI(tc.md)
			if got != tc.want {
				t.Fatalf("sourceURI = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, " ") {
				t.Fatalf("uri %q contains an unencoded space", got)
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("url.Parse(%q): %v", got, err)
			}
			if u.Fragment != "" {
				t.Fatalf("uri %q leaked a fragment: %q", got, u.Fragment)
			}
			if u.RawQuery != "" {
				t.Fatalf("uri %q leaked a query: %q", got, u.RawQuery)
			}
			if u.Path != tc.wantPath {
				t.Fatalf("round-trip path = %q, want %q", u.Path, tc.wantPath)
			}
		})
	}
}

// TestSARIF_ArtifactLocationURIOnFinding drives the encoded URI through the
// public sink so a regression in toSARIFResult's wiring (not just the helper)
// is caught.
func TestSARIF_ArtifactLocationURIOnFinding(t *testing.T) {
	tricky := "/tmp/sx/a b/x#1%.env?tab=1"
	f := engine.Finding{
		Detector: detectors.AWS,
		Result:   detectors.Result{DetectorType: detectors.AWS, Raw: []byte("AKIAIOSFODNN7EXAMPLE")},
		Chunk: &sources.Chunk{
			SourceMetadata: sources.Metadata{
				Filesystem: &sources.FilesystemMeta{Path: tricky, Line: 42},
			},
		},
	}

	var buf bytes.Buffer
	s, _ := NewSink("sarif", &buf, "test")
	s.Emit(f)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	results := doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
	pl := results[0].(map[string]any)["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
	uri := pl["artifactLocation"].(map[string]any)["uri"].(string)

	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", uri, err)
	}
	if u.Scheme != "file" {
		t.Fatalf("scheme = %q, want file", u.Scheme)
	}
	if u.Path != tricky {
		t.Fatalf("round-trip path = %q, want %q", u.Path, tricky)
	}
	if pl["region"].(map[string]any)["startLine"].(float64) != 42 {
		t.Fatalf("startLine = %v, want 42", pl["region"])
	}
}

func extractRuleIDs(t *testing.T, b []byte) []string {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	rules := doc["runs"].([]any)[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.(map[string]any)["id"].(string))
	}
	return out
}

func must(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	if !ok {
		t.Fatalf(format, args...)
	}
}

func mustMap(t *testing.T, v any, name string) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("%s: expected object; got %T", name, v)
	}
	return m
}

func mustList(t *testing.T, v any, name string) []any {
	t.Helper()
	l, ok := v.([]any)
	if !ok {
		t.Fatalf("%s: expected array; got %T", name, v)
	}
	return l
}
