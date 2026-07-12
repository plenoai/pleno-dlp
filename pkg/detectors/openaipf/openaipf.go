package openaipf

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
)

type Analyzer interface {
	Analyze(ctx context.Context, text string) ([]Finding, error)
}

type Finding struct {
	EntityType string
	BIOESTag   string
	Start      int
	End        int
	Score      float64
	Text       string
}

var fetchAnalyzer = func() Analyzer { return nil }

// Scanner satisfies detectors.Detector. It deliberately does NOT
// implement detectors.Verifier — opf is a classifier, not a credential
// issuer; there is no upstream API to confirm a span and PII is not a
// thing one "rotates" anyway.
type Scanner struct{}

func (Scanner) Type() detectors.DetectorType { return detectors.PIIOpenAIPF }

// keywords satisfies the Detector interface but no longer gates
// dispatch: WantsFullChunk routes every chunk to FromData, where the
// looksBinary guard replaces the prefilter's binary-skip role. Kept
// non-empty so registry invariants that reject keyword-less detectors
// hold.
var keywords = []string{
	"@", "http://", "https://", "www.",
	"+", "-", "/",
	"tel", "phone", "fax",
	"電話", "〒", "住所", "氏名",
	"20", "19",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
}

func (Scanner) Keywords() []string { return keywords }

// WantsFullChunk opts out of vicinity-slice dispatch. NER needs the whole
// chunk: PII sits anywhere in prose, not within ±vicinityRadius of a
// keyword hit, and the model's own context handling (window stitching)
// replaces the engine's regex-oriented slicing. Without this, PII outside
// keyword vicinities is silently never analyzed.
func (Scanner) WantsFullChunk() bool { return true }

// FromData runs the chunk through the registered Analyzer and maps
// each returned Finding to a detectors.Result.
//
// Behaviour:
//   - No Analyzer registered (engine off): return (nil, nil) silently.
//     The CLI flag is the user's stated intent and we do not regress
//     to a different engine.
//   - Empty input: return (nil, nil) without calling the supervisor.
//     The supervisor accepts empty text but there is nothing for it
//     to find; the early return saves one round-trip per zero-byte
//     chunk.
//   - Analyzer error: surface it. The engine logs and continues;
//     PII findings for this chunk are skipped.
//   - Empty findings: return (nil, nil).
//   - Non-empty findings: emit one Result per finding. We do not
//     dedup here because the same surface text at different offsets
//     in the same chunk can legitimately be distinct PII (two account
//     numbers, two phone numbers); engine-level dedup keys on Raw if
//     needed.
//
// The verify flag is ignored — Scanner is not a Verifier.
func (Scanner) FromData(ctx context.Context, _ bool, data []byte) ([]detectors.Result, error) {
	if len(data) == 0 || looksBinary(data) {
		return nil, nil
	}
	a := fetchAnalyzer()
	if a == nil {
		return nil, nil
	}
	findings, err := a.Analyze(ctx, string(data))
	if err != nil {
		return nil, err
	}
	if len(findings) == 0 {
		return nil, nil
	}
	out := make([]detectors.Result, 0, len(findings))
	for _, f := range findings {
		kind := mapEntityType(f.EntityType)
		extra := map[string]string{
			"finding_class": "pii",
			"engine":        "openai-pf-native",
			"pii_kind":      kind,
			"score":         fmt.Sprintf("%.2f", f.Score),
			"start":         strconv.Itoa(f.Start),
			"end":           strconv.Itoa(f.End),
		}
		if f.BIOESTag != "" {
			extra["bioes_tag"] = f.BIOESTag
		}
		out = append(out, detectors.Result{
			DetectorType: detectors.PIIOpenAIPF,
			Raw:          []byte(f.Text),
			Redacted:     redact(kind, f.Text),
			ExtraData:    extra,
		})
	}
	return out, nil
}

// redact returns a safe-to-display rendering of a finding. EMAIL_ADDRESS
// preserves the domain so triage can spot duplicates without exposing
// the local-part (mirrors anonymize's redaction for the same entity).
// All other entity kinds keep first and last character with the middle
// replaced by "***" — enough to distinguish two findings without
// leaking the PII itself. Strings shorter than 3 characters pass
// through unchanged because a 5-character "X***Y" template would be
// longer than the original and thus more conspicuous in triage UIs.
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

// looksBinary mirrors the sources' NUL-sniff heuristic. Full-chunk
// dispatch bypasses keyword gating, so without this guard every binary
// chunk from archive/docker/s3 sources would be shipped through NER
// inference for zero possible findings.
func looksBinary(b []byte) bool {
	n := len(b)
	if n > 512 {
		n = 512
	}
	return bytes.IndexByte(b[:n], 0x00) >= 0
}

func init() {
	detectors.Register(Scanner{})
}
