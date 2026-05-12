// Package openaipf is the detector half of the openai/privacy-filter
// (opf) PII engine integration (ADR-0004). It implements
// detectors.Detector — Keywords / FromData / Type — and is deliberately
// not a Verifier: opf classifies free-text PII via a transformer model;
// there is no upstream API to ask "is this real?", and even if there
// were, the appropriate response to a PII hit is access control and
// redaction rather than rotation.
//
// The detector does not own the engine lifecycle. The engine wiring
// layer (cmd/pleno-dlp/cmd/pii_engine.go, switch arm "openai-pf")
// starts pkg/piiengine/openaipf.Supervisor at scan start, publishes
// it via openaipf.SetDefault, and tears it down at scan end. FromData
// reads the singleton through openaipf.Default() and dispatches each
// chunk through Analyze.
//
// FromData maps each Supervisor Finding to a detectors.Result with:
//
//   - DetectorType    = detectors.PIIOpenAIPF
//   - Raw             = the matched substring (bytes)
//   - Redacted        = kind-aware safe rendering (email keeps domain;
//                       generic kinds keep first/last char only)
//   - ExtraData       = {finding_class:"pii", engine:"openai-pf",
//                       pii_kind:<mapped>, score:"0.NN",
//                       start:"<n>", end:"<n>",
//                       bioes_tag:"<raw>" (optional)}
//
// pii_kind is the wire-stable string from ADR-0004 §6:
//
//	opf entity_type        → ExtraData["pii_kind"]
//	"account_numbers"      → "ACCOUNT_NUMBER"
//	"private_addresses"    → "ADDRESS"
//	"private_emails"       → "EMAIL_ADDRESS"
//	"private_persons"      → "PERSON"
//	"private_phone_numbers"→ "PHONE_NUMBER"
//	"private_urls"         → "URL"
//	"private_dates"        → "DATE"
//	"secrets"              → "OPF_SECRET"
//
// The "OPF_SECRET" suffix is deliberate: opf's "secrets" category is a
// free-text catch-all that would collide semantically with the
// pleno-dlp secret-scanner detectors. The "OPF_" prefix signals
// "opf-classified PII, not an authenticated secret material match" —
// downstream consumers must route it through the PII pipeline, not the
// rotate-on-leak pipeline.
//
// Engine off (--pii-engine=off or --pii-engine=anonymize, or spawn
// failed and the engine layer downgraded to skip-and-warn) is signalled
// by openaipf.Default() returning nil; FromData then returns
// (nil, nil) without any work. This matches the anonymize detector's
// behaviour by design — the CLI flag is the user's stated intent and
// we never silently fall back to a different engine.
//
// Keywords: ["@", "http://", "https://", "www.", "+", "-", "/",
// "電話", "tel", "phone", "fax", "〒", "住所", "氏名", "20", "19",
// "0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]. Permissive but
// non-empty so pure-binary chunks (jpegs, gzip, etc.) skip the engine
// entirely. The opf model classifies eight categories (PERSON, EMAIL,
// PHONE, ADDRESS, URL, DATE, ACCOUNT_NUMBER, secrets) — collectively
// they cover almost any chunk that contains either Western punctuation
// or a digit, so a non-empty prefilter is the only way to keep
// throughput sane on binary-heavy repos. The digit anchors are
// individually cheap and route account / phone / date / postcode
// content; the Japanese-language anchors mirror the anonymize
// keywords so a corpus that exercises both engines lands in both
// detector queues.
package openaipf
