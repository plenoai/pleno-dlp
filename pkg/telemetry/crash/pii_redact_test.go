package crash

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

const sampleFeedback = `scan of the 山田太郎 monorepo at Acme Holdings OOMs after 2 GB;
contact alice@example.com, config at /Users/alice/work/.pleno-dlp.yaml,
token ***REDACTED*** leaked in logs.`

func TestRedactPIIEngineMatches(t *testing.T) {
	var seen string
	r := &Redactor{PII: func(_ context.Context, text string) ([]PIIMatch, error) {
		seen = text
		return []PIIMatch{
			{Type: "person", Text: "山田太郎"},
			{Type: "ORGANIZATION", Text: "Acme Holdings"},
			{Type: "", Text: "Acme"},
			{Type: "PERSON", Text: "  "},
		}, nil
	}}
	got := r.Redact(sampleFeedback)
	for _, leak := range []string{"山田太郎", "Acme", "alice@example.com"} {
		if strings.Contains(got, leak) {
			t.Fatalf("%q survived redaction: %s", leak, got)
		}
	}
	for _, want := range []string{"[PII:PERSON]", "[PII:ORGANIZATION]", "[EMAIL]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(seen, "alice@example.com") {
		t.Fatalf("engine received unredacted pattern PII: %s", seen)
	}
}

func TestRedactPIIEngineFailureKeepsPatternRedaction(t *testing.T) {
	want := (&Redactor{}).Redact(sampleFeedback)
	for name, f := range map[string]func(context.Context, string) ([]PIIMatch, error){
		"error": func(context.Context, string) ([]PIIMatch, error) { return nil, errors.New("engine down") },
		"panic": func(context.Context, string) ([]PIIMatch, error) { panic("engine bug") },
	} {
		if got := (&Redactor{PII: f}).Redact(sampleFeedback); got != want {
			t.Fatalf("%s: got %q, want %q", name, got, want)
		}
	}
}

// TestAllDetectorPassWithinBudget measures the all-detector pass that
// feedback runs over a typical message and checks it stays well inside
// detectorBudget, so the budget is not silently truncating the scrub.
func TestAllDetectorPassWithinBudget(t *testing.T) {
	r := &Redactor{Detectors: detectors.All()}
	start := time.Now()
	r.Redact(sampleFeedback)
	elapsed := time.Since(start)
	t.Logf("all-detector redaction (%d detectors): %s (budget %s)", len(r.Detectors), elapsed, detectorBudget)
	if elapsed >= detectorBudget {
		t.Fatalf("all-detector pass took %s, at or over its %s budget", elapsed, detectorBudget)
	}
}

func BenchmarkRedactAllDetectors(b *testing.B) {
	r := &Redactor{Detectors: detectors.All()}
	b.ReportAllocs()
	for b.Loop() {
		r.Redact(sampleFeedback)
	}
}
