# pleno-anonymize PII engine (supervisor + detector)

Two packages implement the pleno-anonymize integration:
`pkg/piiengine/anonymize` (server lifecycle) and
`pkg/detectors/anonymize` (detector half). This document records the
design decisions behind both.

## Supervisor lifecycle (`pkg/piiengine/anonymize`)

The supervisor exists because pleno-anonymize is a Python application
(spaCy + Presidio + pleno_anonymize_ja) with no Go bindings and a
multi-second cold start. Per ADR-0001 we amortize that cost by spawning
the server once at scan start, calling `POST /api/analyze` per chunk,
and shutting it down at scan end. The spawn argv is supplied by the
caller via `Config.Cmd` (with a `{PORT}` placeholder that the supervisor
substitutes); the supervisor never assumes a binary on `$PATH`. Per
ADR-0003 the recommended default argv is `pleno-dlp pii-server --port
{PORT}`, which itself shells out to `uvx` to run the upstream Python
server — no Docker is involved (ADR-0003 supersedes ADR-0002 on that
point).

Invariants enforced by this package:

- Bind address defaults to 127.0.0.1; supplying a public interface
  is rejected at `New()` time. A DLP tool must never relay scanned
  text to a public listener.
- `Start` blocks on `/ready` (which lazy-loads the NER models) rather
  than `/health` (which reports liveness only). Cold-start in our
  CI is around 6–9s.
- `Analyze` is safe for concurrent goroutines. The HTTP client is
  concurrent-safe by stdlib contract; lifecycle state is guarded
  by a mutex so Stop-during-Analyze cannot race the http.Client
  shutdown.
- `Stop` is idempotent and tolerates being called from a `defer`
  even when `Start` failed. Spawn failures return typed errors so
  callers can downgrade gracefully (warn + skip PII, continue
  secret scan).

The detector half of this feature lives in `pkg/detectors/anonymize`;
it retrieves the singleton Supervisor via the package-level handle
(`SetDefault` / `Default`) wired by the engine entrypoint when
`--pii-engine=anonymize`.

## Detector half (`pkg/detectors/anonymize`)

Implements `detectors.Detector` — Keywords / FromData / Type — and is
deliberately not a Verifier: PII has no rotate path and no upstream "is
this real" call.

The detector does not own the engine lifecycle. The engine
(`pkg/engine`) starts `pkg/piiengine/anonymize.Supervisor` at scan start
and hands a handle to this package via `SetAnalyzer`. `FromData` then
calls `Analyzer.Analyze` per chunk and maps each Finding to a
`detectors.Result` with:

- `DetectorType` = `detectors.PIIAnonymize`
- `Raw` = the matched substring (bytes)
- `Redacted` = kind-aware safe rendering (email keeps domain;
  generic kinds keep first/last char only)
- `ExtraData` = `{finding_class:"pii", pii_kind:<entity_type>,
  score:"0.NN"}`

When the engine is off (`--pii-engine=off`, the default), no Analyzer
is registered and `FromData` returns `(nil, nil)` — silent skip. This is
intentional: the CLI flag is the user's stated intent. We do not
fall back to regex-only detection because that would resurrect the
false-positive shape this whole feature was built to retire.

The `Analyzer` interface and `Finding` type are defined in the detector
package rather than imported from `pkg/piiengine/anonymize` so the
detector and the supervisor can be tested independently without an
import cycle and so future PII engines can be substituted by the engine
wiring layer without touching the detector package.

Keywords: `["@", "〒", "電話", "住所", "氏名", "-"]`. Permissive but
non-empty so pure-binary chunks are skipped by the engine prefilter.
Each prefix anchors a class of NER-relevant content the upstream engine
routes on:

- `"@"` — email addresses, social handles
- `"〒"` — Japanese postal-code marker (zipcodes)
- `"電話"` — telephone numbers in Japanese-language documents
- `"住所"` — addresses in Japanese-language documents
- `"氏名"` — person names in Japanese-language documents
- `"-"` — generic separator that appears in IBAN, US SSN,
  phone numbers, and many credit-card formats; cheap
  to match, keeps Western-shaped PII routed to the engine

We accept that `"-"` matches a large fraction of source code; the
engine itself absorbs the cost of running NER on those chunks and
returns zero findings cheaply when nothing fires.