# pleno-dlp

Unified DLP scanner — secrets and PII. Single Go binary

## Harness: pleno-dlp

**Goal:** maintain and evolve the unified DLP scanner — single Go binary
covering 600+ secret detectors + PII detectors (using pleno-anonymize or
openai/privacy-filter, selected via `--pii-engine`) over filesystem, git,
stdin, and SaaS sources.

**Trigger:** invoke the `secret-scanner-orchestrator` skill when a
request involves any of:
- adding or modifying detectors or sources
- engine, CLI, output-format, or CI changes
- detector / source interface changes (high blast radius)
- SaaS connector ports

Single-file greps and trivial questions should be answered directly
without invoking the orchestrator.

## Workflow rules

- All Go packages live in a single Go module rooted at this repo. New
  packages go under `pkg/<area>/<name>/` without their own `go.mod`
  (single-module configuration).
- Go tests must pass `go test ./... -race`. Race-detector failures block
  PRs.
- Releases trigger exclusively by tag push: `vX.Y.Z` → Go binary release
  via GoReleaser trusted publishing.
- `main` push runs build + tests only — it does not publish (this is a
  CLI binary, not a service).
- Because this tool handles secret material, every new secret detector
  must either implement `Verify()` or be explicitly marked
  unverified-only. PII detectors must set
  `ExtraData["finding_class"]="pii"` so downstream callers can route by
  class.
- The verify-coverage classification is enforced in CI. Any new
  non-Verifier detector requires three coordinated edits:
  (1) register under `pkg/detectors/<provider>/`,
  (2) add a row to `docs/verify-coverage.md` (machine block + prose
  table) as `class=b` (unverified-by-design, with rationale) or
  `class=c` (verifiable but not yet implemented, with the upstream
  verify path),
  (3) mirror the entry in `pkg/detectors/verifycoverage/Classes`.
  `pkg/detectors/verifycoverage_test.go` rejects (1) ↔ (2) drift and
  `pkg/detectors/verifycoverage/verifycoverage_sync_test.go` rejects
  (2) ↔ (3) drift. Verifier-implementing detectors stay out of the
  doc — class (a) is the open-set complement.
  Operators query the classification at runtime via
  `pleno-dlp detectors list --verify-status`.

## Change history

| Date | Owners | Change |
|---|---|---|
| 2026-09-22 | architect, core-engineer, detector-engineer, connector-engineer, qa | Stream large filesystem and decoded bodies, retain original finding spans, and preserve checkpoints on deferred read failures; consumers must support `Chunk.Open` ([ADR-0006](docs/adr/0006-performance-budgets.md)). |
| 2026-09-21 | architect, core-engineer, detector-engineer, connector-engineer, qa | Repair encoded-input coverage, lazily compile detector regexes, and enforce time plus RSS across 34 input shapes against three scanners; [contract](docs/performance.md). |
| 2026-09-21 | architect, core-engineer, detector-engineer, connector-engineer, qa | Five subsystem performance budgets and scanner allocation reductions; [method and evidence](docs/performance.md). |
