//go:build detector_unit

package openaipf

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// fakeAnalyzer is the standard test substitute. It records the last
// text passed and returns canned findings or a canned error.
type fakeAnalyzer struct {
	findings []Finding
	err      error
	lastText string
	calls    int
}

func (f *fakeAnalyzer) Analyze(_ context.Context, text string) ([]Finding, error) {
	f.calls++
	f.lastText = text
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

// withAnalyzer overrides fetchAnalyzer for the duration of the test
// and restores the prior implementation on cleanup. fetchAnalyzer is
// a package-level function variable so the substitution does not
// require touching the production singleton in pkg/piiengine/openaipf.
func withAnalyzer(t *testing.T, a Analyzer) {
	t.Helper()
	prev := fetchAnalyzer
	fetchAnalyzer = func() Analyzer { return a }
	t.Cleanup(func() { fetchAnalyzer = prev })
}

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PIIOpenAIPF {
		t.Fatalf("Type() must return PIIOpenAIPF")
	}
}

func TestKeywordsNonEmpty(t *testing.T) {
	kw := (Scanner{}).Keywords()
	if len(kw) == 0 {
		t.Fatal("Keywords() must be non-empty so binary chunks are skipped by the engine prefilter")
	}
	// "@" anchors email-shaped routing; missing it means
	// email-bearing chunks would never reach the supervisor.
	want := map[string]bool{"@": false, "http://": false, "+": false, "0": false}
	for _, k := range kw {
		if _, ok := want[k]; ok {
			want[k] = true
		}
	}
	for k, found := range want {
		if !found {
			t.Errorf("Keywords() missing required anchor %q", k)
		}
	}
}

func TestFromData_EngineOff_ReturnsNil(t *testing.T) {
	// fetchAnalyzer returning nil is the engine-off signal. FromData
	// must silent-skip — no error, no results.
	prev := fetchAnalyzer
	fetchAnalyzer = func() Analyzer { return nil }
	t.Cleanup(func() { fetchAnalyzer = prev })

	res, err := Scanner{}.FromData(context.Background(), false, []byte("alice@example.com"))
	if err != nil {
		t.Fatalf("engine-off must not error, got %v", err)
	}
	if res != nil {
		t.Fatalf("engine-off must return nil results, got %v", res)
	}
}

func TestFromData_EmptyInput_ShortCircuits(t *testing.T) {
	// Zero-byte chunks must not even reach the supervisor; the early
	// return saves one round-trip per empty chunk and the analyzer
	// call count proves it.
	f := &fakeAnalyzer{}
	withAnalyzer(t, f)

	res, err := Scanner{}.FromData(context.Background(), false, nil)
	if err != nil {
		t.Fatalf("empty input must not error, got %v", err)
	}
	if res != nil {
		t.Fatalf("empty input must return nil results, got %v", res)
	}
	if f.calls != 0 {
		t.Errorf("empty input must not call Analyze, got %d calls", f.calls)
	}
}

func TestFromData_EmptyFindings(t *testing.T) {
	withAnalyzer(t, &fakeAnalyzer{})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("nothing to see"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil for empty findings, got %v", res)
	}
}

func TestFromData_AnalyzerError(t *testing.T) {
	want := errors.New("transport oops")
	withAnalyzer(t, &fakeAnalyzer{err: want})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("x"))
	if !errors.Is(err, want) {
		t.Fatalf("expected propagated error, got %v", err)
	}
	if res != nil {
		t.Fatalf("expected nil results on error, got %v", res)
	}
}

func TestFromData_EmailFinding_EmitsExtraData(t *testing.T) {
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{{
			EntityType: "private_emails",
			BIOESTag:   "E-private_emails",
			Start:      9,
			End:        26,
			Score:      0.97,
			Text:       "alice@example.com",
		}},
	})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("contact: alice@example.com"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	r := res[0]
	if r.DetectorType != detectors.PIIOpenAIPF {
		t.Errorf("wrong DetectorType: %v", r.DetectorType)
	}
	if string(r.Raw) != "alice@example.com" {
		t.Errorf("wrong Raw: %q", r.Raw)
	}
	if r.Redacted != "a***@example.com" {
		t.Errorf("EMAIL_ADDRESS redaction must keep domain: got %q", r.Redacted)
	}
	if r.Verified {
		t.Error("PIIOpenAIPF must never set Verified=true (no Verifier path)")
	}
	if r.VerificationErr != nil {
		t.Errorf("VerificationErr must be nil for PII; got %v", r.VerificationErr)
	}
	mustEqual(t, r.ExtraData, "finding_class", "pii")
	mustEqual(t, r.ExtraData, "engine", "openai-pf")
	mustEqual(t, r.ExtraData, "pii_kind", "EMAIL_ADDRESS")
	mustEqual(t, r.ExtraData, "score", "0.97")
	mustEqual(t, r.ExtraData, "start", "9")
	mustEqual(t, r.ExtraData, "end", "26")
	mustEqual(t, r.ExtraData, "bioes_tag", "E-private_emails")
}

func TestFromData_EachOPFCategoryMapsCorrectly(t *testing.T) {
	// ADR-0004 §6 wire contract. Every opf category must surface with
	// the documented pii_kind. A drift in mapping.go is a wire-format
	// break for downstream JSON consumers.
	type row struct {
		entity, kind string
	}
	rows := []row{
		{"account_numbers", "ACCOUNT_NUMBER"},
		{"private_addresses", "ADDRESS"},
		{"private_emails", "EMAIL_ADDRESS"},
		{"private_persons", "PERSON"},
		{"private_phone_numbers", "PHONE_NUMBER"},
		{"private_urls", "URL"},
		{"private_dates", "DATE"},
		{"secrets", "OPF_SECRET"},
	}
	findings := make([]Finding, len(rows))
	for i, r := range rows {
		findings[i] = Finding{
			EntityType: r.entity,
			Start:      i,
			End:        i + 1,
			Score:      0.50 + 0.01*float64(i),
			Text:       "X" + r.entity + "Y",
		}
	}
	withAnalyzer(t, &fakeAnalyzer{findings: findings})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != len(rows) {
		t.Fatalf("want %d results, got %d", len(rows), len(res))
	}
	for i, r := range res {
		want := rows[i].kind
		got := r.ExtraData["pii_kind"]
		if got != want {
			t.Errorf("row %d (%s): pii_kind want %q, got %q", i, rows[i].entity, want, got)
		}
		if r.ExtraData["finding_class"] != "pii" {
			t.Errorf("row %d: missing finding_class=pii", i)
		}
		if r.ExtraData["engine"] != "openai-pf" {
			t.Errorf("row %d: wrong engine: %q", i, r.ExtraData["engine"])
		}
	}
}

func TestMapping_SingularAndPluralNormalizeIdentically(t *testing.T) {
	// The subprocess path emits plural labels; the native
	// (privacy-filter.cpp) path emits the model's singular BIOES-stripped
	// category names. Both must normalize to the same wire-stable pii_kind
	// so downstream consumers cannot tell which engine implementation ran.
	// Singular set is the GGUF's 8 categories (openai/privacy-filter model
	// card, "Label space": 1 O + 8×4 BIOES = 33 classes).
	type pair struct {
		plural, singular, kind string
	}
	pairs := []pair{
		{"account_numbers", "account_number", "ACCOUNT_NUMBER"},
		{"private_addresses", "private_address", "ADDRESS"},
		{"private_emails", "private_email", "EMAIL_ADDRESS"},
		{"private_persons", "private_person", "PERSON"},
		{"private_phone_numbers", "private_phone", "PHONE_NUMBER"},
		{"private_urls", "private_url", "URL"},
		{"private_dates", "private_date", "DATE"},
		{"secrets", "secret", "OPF_SECRET"},
	}
	for _, p := range pairs {
		gotP := mapEntityType(p.plural)
		gotS := mapEntityType(p.singular)
		if gotP != p.kind {
			t.Errorf("plural %q: pii_kind want %q, got %q", p.plural, p.kind, gotP)
		}
		if gotS != p.kind {
			t.Errorf("singular %q: pii_kind want %q, got %q", p.singular, p.kind, gotS)
		}
		if gotP != gotS {
			t.Errorf("%q/%q normalize differently: %q vs %q", p.plural, p.singular, gotP, gotS)
		}
	}
}

func TestFromData_EachNativeCategoryMapsCorrectly(t *testing.T) {
	// End-to-end mirror of TestFromData_EachOPFCategoryMapsCorrectly for
	// the native path's singular labels: a singular EntityType from
	// opfnative must surface with the same pii_kind as its plural twin.
	type row struct {
		entity, kind string
	}
	rows := []row{
		{"account_number", "ACCOUNT_NUMBER"},
		{"private_address", "ADDRESS"},
		{"private_email", "EMAIL_ADDRESS"},
		{"private_person", "PERSON"},
		{"private_phone", "PHONE_NUMBER"},
		{"private_url", "URL"},
		{"private_date", "DATE"},
		{"secret", "OPF_SECRET"},
	}
	findings := make([]Finding, len(rows))
	for i, r := range rows {
		findings[i] = Finding{
			EntityType: r.entity,
			Start:      i,
			End:        i + 1,
			Score:      0.50 + 0.01*float64(i),
			Text:       "X" + r.entity + "Y",
		}
	}
	withAnalyzer(t, &fakeAnalyzer{findings: findings})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("payload"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != len(rows) {
		t.Fatalf("want %d results, got %d", len(rows), len(res))
	}
	for i, r := range res {
		if got := r.ExtraData["pii_kind"]; got != rows[i].kind {
			t.Errorf("row %d (%s): pii_kind want %q, got %q", i, rows[i].entity, rows[i].kind, got)
		}
	}
}

func TestFromData_UnknownEntity_PassesThroughRaw(t *testing.T) {
	// A future opf release that adds a category we have not mapped
	// MUST surface the finding (forwarding the raw entity_type as
	// pii_kind) instead of dropping it. This keeps the detector
	// observable in production even before the mapping table catches up.
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{{
			EntityType: "future_unmapped_category",
			Score:      0.80,
			Text:       "something",
		}},
	})

	res, err := Scanner{}.FromData(context.Background(), false, []byte("x"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if res[0].ExtraData["pii_kind"] != "future_unmapped_category" {
		t.Errorf("unknown entity must pass through: got %q", res[0].ExtraData["pii_kind"])
	}
}

func TestFromData_NoBIOES_OmitsBIOESKey(t *testing.T) {
	// BIOESTag is optional. When the supervisor omits it, the
	// detector must not emit an empty bioes_tag in ExtraData — empty
	// strings in JSON outputs would falsely look like a tagged-but-blank
	// finding.
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{{
			EntityType: "private_persons",
			Score:      0.91,
			Text:       "Alice Tanaka",
		}},
	})
	res, err := Scanner{}.FromData(context.Background(), false, []byte("p"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	if _, ok := res[0].ExtraData["bioes_tag"]; ok {
		t.Error("bioes_tag must be absent when supervisor omits the field")
	}
}

func TestFromData_MultipleFindings_AllEmitted(t *testing.T) {
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{
			{EntityType: "private_persons", Score: 0.85, Text: "Alice Tanaka"},
			{EntityType: "private_phone_numbers", Score: 0.90, Text: "+81-3-5555-1234"},
			{EntityType: "secrets", Score: 0.70, Text: "AKIA0000EXAMPLE"},
		},
	})
	res, err := Scanner{}.FromData(context.Background(), false, []byte("doc"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 3 {
		t.Fatalf("want 3 results, got %d", len(res))
	}
	// Generic (non-email) redaction: first + *** + last.
	wantRedacted := map[string]string{
		"PERSON":       "A***a",
		"PHONE_NUMBER": "+***4",
		"OPF_SECRET":   "A***E",
	}
	for _, r := range res {
		kind := r.ExtraData["pii_kind"]
		if want, ok := wantRedacted[kind]; ok && r.Redacted != want {
			t.Errorf("%s redaction: want %q, got %q", kind, want, r.Redacted)
		}
		if r.ExtraData["engine"] != "openai-pf" {
			t.Errorf("%s: wrong engine: %q", kind, r.ExtraData["engine"])
		}
	}
}

func TestFromData_PassesTextThrough(t *testing.T) {
	// The detector must not pre-trim, re-encode, or otherwise mutate
	// the chunk before sending it to the supervisor. opf scores rely
	// on the exact byte sequence the engine receives.
	f := &fakeAnalyzer{}
	withAnalyzer(t, f)

	payload := "contact alice@example.com or +81-3-1234-5678"
	_, _ = Scanner{}.FromData(context.Background(), false, []byte(payload))
	if f.lastText != payload {
		t.Errorf("text passthrough: want %q, got %q", payload, f.lastText)
	}
}

func TestRedact_EmailMalformed_FallsBackToGeneric(t *testing.T) {
	// "@example.com" has @ at position 0 — must NOT echo plaintext.
	got := redact("EMAIL_ADDRESS", "@example.com")
	if strings.HasPrefix(got, "@") && !strings.Contains(got, "***") {
		t.Errorf("malformed email must not pass through unchanged: got %q", got)
	}
}

func TestRedact_ShortRawPassesThrough(t *testing.T) {
	// 2-char strings are shorter than the redaction template (1+3+1=5);
	// echo them as-is rather than producing a longer redacted string
	// than the original.
	if got := redact("PERSON", "AB"); got != "AB" {
		t.Errorf("short raw should pass through, got %q", got)
	}
}

func TestRegistered(t *testing.T) {
	// init() must have registered the Scanner against PIIOpenAIPF.
	for _, d := range detectors.All() {
		if d.Type() == detectors.PIIOpenAIPF {
			return
		}
	}
	t.Fatal("Scanner was not registered against detectors.PIIOpenAIPF via init()")
}

func TestMapping_UnknownReturnsInput(t *testing.T) {
	// White-box check of the mapping helper — guards against a refactor
	// that accidentally drops the pass-through arm.
	if got := mapEntityType("unmapped_xyz"); got != "unmapped_xyz" {
		t.Errorf("unknown entity_type must pass through, got %q", got)
	}
}

func mustEqual(t *testing.T, m map[string]string, key, want string) {
	t.Helper()
	got, ok := m[key]
	if !ok {
		t.Errorf("ExtraData missing key %q", key)
		return
	}
	if got != want {
		t.Errorf("ExtraData[%q]: want %q, got %q", key, want, got)
	}
}
