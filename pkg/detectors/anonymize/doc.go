// Package anonymize is the detector half of the pleno-anonymize PII
// engine integration (ADR-0001 / ADR-0002). It implements
// detectors.Detector — Keywords / FromData / Type — and is deliberately
// not a Verifier: PII has no rotate path and no upstream "is this
// real" call.
//
// The detector does not own the engine lifecycle. The engine
// (pkg/engine) starts pkg/piiengine/anonymize.Supervisor at scan start
// and hands a handle to this package via SetAnalyzer. FromData then
// calls Analyzer.Analyze per chunk and maps each Finding to a
// detectors.Result with:
//
//   - DetectorType    = detectors.PIIAnonymize
//   - Raw             = the matched substring (bytes)
//   - Redacted        = kind-aware safe rendering (email keeps domain;
//     generic kinds keep first/last char only)
//   - ExtraData       = {finding_class:"pii", pii_kind:<entity_type>,
//     score:"0.NN"}
//
// When the engine is off (--pii-engine=off, the default), no Analyzer
// is registered and FromData returns (nil, nil) — silent skip. This is
// intentional: the CLI flag is the user's stated intent. We do not
// fall back to regex-only detection because that would resurrect the
// false-positive shape this whole feature was built to retire.
//
// The Analyzer interface and Finding type are defined here rather than
// imported from pkg/piiengine/anonymize so the detector and the
// supervisor can be tested independently without an import cycle and
// so future PII engines (presidio direct, cloud-DLP shim) can be
// substituted by the engine wiring layer without touching this
// package.
//
// Keywords: ["@", "〒", "電話", "住所", "氏名", "-"]. Permissive but
// non-empty so pure-binary chunks (jpegs, gzip, …) are skipped by the
// engine prefilter. Each prefix anchors a class of NER-relevant
// content the upstream engine routes on:
//
//   - "@"   — email addresses, social handles
//   - "〒"  — Japanese postal-code marker (zipcodes)
//   - "電話" — telephone numbers in Japanese-language documents
//   - "住所" — addresses in Japanese-language documents
//   - "氏名" — person names in Japanese-language documents
//   - "-"   — generic separator that appears in IBAN, US SSN,
//     phone numbers, and many credit-card formats; cheap
//     to match, keeps Western-shaped PII routed to the engine
//
// We accept that "-" matches a large fraction of source code; the
// engine itself absorbs the cost of running NER on those chunks and
// returns zero findings cheaply when nothing fires.
package anonymize
