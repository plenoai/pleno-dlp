package openaipf

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/plenoai/pleno-dlp/pkg/detectors"
	piie "github.com/plenoai/pleno-dlp/pkg/piiengine/openaipf"
)

// Analyzer is the subset of pkg/piiengine/openaipf.Supervisor that the
// detector needs. Defined as an interface (and as a package-level
// function variable below) so tests can substitute a fake without
// spawning a real opf HTTP server. The interface matches the
// supervisor's Analyze signature verbatim — see ADR-0004 §3.
type Analyzer interface {
	Analyze(ctx context.Context, text string) ([]Finding, error)
}

// Finding mirrors the per-entity payload returned by the supervisor.
// Defined locally with the same fields as piie.Finding so the
// detector and the supervisor can be tested independently without
// pulling the supervisor (and its child-process / http.Client state)
// into the detector test binary. The production path adapts the
// supervisor's Finding into this shape with a zero-cost struct copy
// in supervisorAdapter.
type Finding struct {
	EntityType string
	BIOESTag   string
	Start      int
	End        int
	Score      float64
	Text       string
}

// fetchAnalyzer returns the active Analyzer, or nil when the engine
// is off (--pii-engine=off / --pii-engine=anonymize, or spawn failed
// and the engine layer downgraded to skip-and-warn). Production looks
// up the singleton Supervisor published by piie.SetDefault and wraps
// it in supervisorAdapter; tests override this variable to inject a
// fake.
var fetchAnalyzer = productionAnalyzer

// engineImpl labels the active backend in ExtraData["engine_impl"]. It is
// "subprocess" (the Python openaipf supervisor) by default; an opf_native
// build flips it to "native" via SetEngineImplNative when the in-process
// privacy-filter.cpp engine is the selected backend (ADR-0005 §E).
// ExtraData["engine"] stays "openai-pf" regardless, so downstream routing
// on the logical engine is unchanged — engine_impl carries provenance only.
var engineImpl = "subprocess"

func productionAnalyzer() Analyzer {
	sup := piie.Default()
	if sup == nil {
		return nil
	}
	return supervisorAdapter{s: sup}
}

// supervisorAdapter bridges pkg/piiengine/openaipf.Supervisor (which
// returns []piie.Finding) to the detector's local Analyzer / Finding
// types. The per-element copy is zero-cost because the field layout
// is identical; the indirection exists only so the detector compiles
// against a stable local interface and so the test binary does not
// transitively import the supervisor's net/http and os/exec
// dependencies.
type supervisorAdapter struct {
	s *piie.Supervisor
}

func (a supervisorAdapter) Analyze(ctx context.Context, text string) ([]Finding, error) {
	fs, err := a.s.Analyze(ctx, text)
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
			BIOESTag:   f.BIOESTag,
			Start:      f.Start,
			End:        f.End,
			Score:      f.Score,
			Text:       f.Text,
		}
	}
	return out, nil
}

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
			"engine":        "openai-pf",
			"engine_impl":   engineImpl,
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
