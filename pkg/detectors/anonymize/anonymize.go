package anonymize

import (
	"context"
	"fmt"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	piie "github.com/plenoai/pleno-dlp/pkg/piiengine/anonymize"
)

// Analyzer is the subset of pkg/piiengine/anonymize.Supervisor that
// the detector needs. Defined as an interface so tests can substitute
// a fake without spawning a real HTTP server.
type Analyzer interface {
	Analyze(ctx context.Context, text, language string) ([]Finding, error)
}

// Finding mirrors the per-entity payload returned by the supervisor.
// Defined locally with the same fields as
// pkg/piiengine/anonymize.Finding so the redaction layer can be
// exercised by tests against an in-package interface; the production
// path adapts the supervisor's Finding into this shape with a
// zero-cost struct copy.
type Finding struct {
	EntityType string
	Start      int
	End        int
	Score      float64
	Text       string
}

// fetchAnalyzer returns the active Analyzer, or nil when the engine
// is off (--pii-engine=off, or spawn failed and the engine layer
// downgraded to skip-and-warn). Production looks up the singleton
// Supervisor published by pkg/piiengine/anonymize.SetDefault and
// wraps it in supervisorAdapter; tests override this variable to
// inject a fake.
var fetchAnalyzer = productionAnalyzer

func productionAnalyzer() Analyzer {
	sup := piie.Default()
	if sup == nil {
		return nil
	}
	return supervisorAdapter{s: sup}
}

// supervisorAdapter bridges pkg/piiengine/anonymize.Supervisor (which
// returns []piie.Finding) to the detector's local Analyzer / Finding
// types. The struct copy is zero-cost because the field layout is
// identical; the indirection exists only so the detector package
// compiles against a stable local interface.
type supervisorAdapter struct {
	s *piie.Supervisor
}

func (a supervisorAdapter) Analyze(ctx context.Context, text, language string) ([]Finding, error) {
	fs, err := a.s.Analyze(ctx, text, language)
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, nil
	}
	out := make([]Finding, len(fs))
	for i, f := range fs {
		out[i] = Finding{
			EntityType: f.EntityType,
			Start:      f.Start,
			End:        f.End,
			Score:      f.Score,
			Text:       f.Text,
		}
	}
	return out, nil
}

// detectorLanguage is the language hint passed to the supervisor.
// Hardcoded to "ja" today because the upstream engine routes via
// language config; the CLI flag --pii-engine-language already lives
// at the supervisor layer and we read no per-chunk language signal.
// When per-chunk detection lands this becomes a function of the chunk
// metadata, not the detector.
const detectorLanguage = "ja"

// Scanner satisfies detectors.Detector. It deliberately does NOT
// implement detectors.Verifier — PII is not a credential; there is no
// upstream API to confirm validity and no "rotate" action to take on
// a true positive.
type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIIAnonymize }

// keywords is intentionally permissive but non-empty. An empty
// Keywords() forces the engine to run FromData on every chunk
// including pure-binary chunks (compressed archives, images), which
// would shovel garbage through the supervisor with no chance of a
// hit. The selected prefixes anchor email-shaped content, Japanese
// PII markers (postal/phone/address/name), and the dash separator
// that appears in most Western PII shapes (IBAN, SSN, phone, card).
var keywords = []string{"@", "〒", "電話", "住所", "氏名", "-"}

func (Scanner) Keywords() []string { return keywords }

// FromData runs the chunk through the registered Analyzer and maps
// each returned Finding to a detectors.Result.
//
// Behaviour:
//   - No Analyzer registered (engine off): return (nil, nil) silently.
//     The CLI flag is the user's stated intent and we do not regress to
//     regex-only detection.
//   - Analyzer error: surface it. The engine will log and continue;
//     PII findings for this chunk are skipped.
//   - Empty findings: return (nil, nil).
//   - Non-empty findings: emit one Result per finding. We do not dedup
//     here because the same surface text at different offsets in the
//     same chunk can legitimately be distinct PII (e.g. two people with
//     the same first name); engine-level dedup keys on Raw if needed.
//
// The verify flag is ignored — Scanner is not a Verifier.
func (Scanner) FromData(ctx context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	a := fetchAnalyzer()
	if a == nil {
		return nil, nil
	}
	findings, err := a.Analyze(ctx, string(data), detectorLanguage)
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(findings))
	for _, f := range findings {
		out = append(out, detectors.Result{
			DetectorType: detectors.PIIAnonymize,
			Raw:          []byte(f.Text),
			Redacted:     redact(f.EntityType, f.Text),
			ExtraData: map[string]string{
				"finding_class": "pii",
				"pii_kind":      f.EntityType,
				"score":         fmt.Sprintf("%.2f", f.Score),
			},
		})
	}
	return out, nil
}

// redact returns a safe-to-display rendering of a finding. EMAIL_ADDRESS
// preserves the domain so triage can spot duplicates without exposing
// the local-part (the same shape the retired piiemail detector used).
// All other entity kinds keep first and last character with the middle
// replaced by "***" — enough to distinguish two findings without
// leaking the PII itself. Strings shorter than 3 characters pass
// through unchanged because there is nothing meaningful to mask.
func redact(kind, raw string) string {
	if len(raw) < 3 {
		return raw
	}
	if kind == "EMAIL_ADDRESS" {
		at := strings.IndexByte(raw, '@')
		if at <= 1 {
			// Malformed email-shape (no @ or @ at position 0/1) —
			// fall through to generic redaction so we don't leak.
			return raw[:1] + "***" + raw[len(raw)-1:]
		}
		return raw[:1] + "***" + raw[at:]
	}
	return raw[:1] + "***" + raw[len(raw)-1:]
}

func init() {
	detectors.Register(Scanner{})
}
