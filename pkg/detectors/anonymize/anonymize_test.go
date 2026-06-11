package anonymize

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

// fakeAnalyzer is the standard test substitute. It records the last
// language hint passed and returns canned findings or a canned error.
type fakeAnalyzer struct {
	findings []Finding
	err      error
	lastLang string
	lastText string
}

func (f *fakeAnalyzer) Analyze(_ context.Context, text, lang string) ([]Finding, error) {
	f.lastText = text
	f.lastLang = lang
	if f.err != nil {
		return nil, f.err
	}
	return f.findings, nil
}

// withAnalyzer overrides fetchAnalyzer for the duration of the test
// and restores the prior implementation on cleanup. fetchAnalyzer is
// a package-level function variable so the test substitution does
// not require touching the production singleton in
// pkg/piiengine/anonymize.
func withAnalyzer(t *testing.T, a Analyzer) {
	t.Helper()
	prev := fetchAnalyzer
	fetchAnalyzer = func() Analyzer { return a }
	t.Cleanup(func() { fetchAnalyzer = prev })
}

func TestType(t *testing.T) {
	if (Scanner{}).Type() != detectors.PIIAnonymize {
		t.Fatalf("Type() must return PIIAnonymize")
	}
}

func TestKeywordsNonEmpty(t *testing.T) {
	kw := (Scanner{}).Keywords()
	if len(kw) == 0 {
		t.Fatal("Keywords() must be non-empty so binary chunks are skipped by the engine prefilter")
	}
	// The "@" anchor is required for email-shaped routing — drop it
	// and the engine never feeds email-bearing chunks to the supervisor.
	wantAt := false
	for _, k := range kw {
		if k == "@" {
			wantAt = true
			break
		}
	}
	if !wantAt {
		t.Error(`Keywords() must contain "@" to anchor email-shaped chunks`)
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

func TestFromData_SingleEmailFinding(t *testing.T) {
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{{
			EntityType: "EMAIL_ADDRESS",
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
	if r.DetectorType != detectors.PIIAnonymize {
		t.Errorf("wrong DetectorType: %v", r.DetectorType)
	}
	if string(r.Raw) != "alice@example.com" {
		t.Errorf("wrong Raw: %q", r.Raw)
	}
	if r.Redacted != "a***@example.com" {
		t.Errorf("EMAIL_ADDRESS redaction must keep domain: got %q", r.Redacted)
	}
	if r.ExtraData["finding_class"] != "pii" {
		t.Errorf("missing finding_class=pii")
	}
	if r.ExtraData["pii_kind"] != "EMAIL_ADDRESS" {
		t.Errorf("pii_kind must mirror entity_type: got %q", r.ExtraData["pii_kind"])
	}
	if r.ExtraData["score"] != "0.97" {
		t.Errorf("score must format to 2dp: got %q", r.ExtraData["score"])
	}
}

func TestFromData_MultipleEntityKinds(t *testing.T) {
	withAnalyzer(t, &fakeAnalyzer{
		findings: []Finding{
			{EntityType: "PERSON", Score: 0.85, Text: "Alice Tanaka"},
			{EntityType: "JP_MY_NUMBER", Score: 0.99, Text: "123456789012"},
			{EntityType: "ADDRESS", Score: 0.80, Text: "東京都港区"},
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
		"JP_MY_NUMBER": "1***2",
	}
	for _, r := range res {
		kind := r.ExtraData["pii_kind"]
		if want, ok := wantRedacted[kind]; ok && r.Redacted != want {
			t.Errorf("%s redaction: want %q, got %q", kind, want, r.Redacted)
		}
		if r.ExtraData["finding_class"] != "pii" {
			t.Errorf("%s: missing finding_class=pii", kind)
		}
	}
}

func TestFromData_PassesLanguageHint(t *testing.T) {
	f := &fakeAnalyzer{}
	withAnalyzer(t, f)

	_, _ = Scanner{}.FromData(context.Background(), false, []byte("payload"))
	if f.lastLang != "" {
		t.Errorf("language hint: want %q (defer to supervisor config), got %q", "", f.lastLang)
	}
	if f.lastText != "payload" {
		t.Errorf("text passthrough: want %q, got %q", "payload", f.lastText)
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
	// init() must have registered the Scanner against PIIAnonymize.
	for _, d := range detectors.All() {
		if d.Type() == detectors.PIIAnonymize {
			return
		}
	}
	t.Fatal("Scanner was not registered against detectors.PIIAnonymize via init()")
}
