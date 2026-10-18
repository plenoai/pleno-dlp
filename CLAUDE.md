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
| 2026-10-18 | qa, core-engineer | Parse `protect` unified diffs by hunk state so added content beginning with `++` (rendered `+++...`) is scanned; skip only `+++` file headers before the first `@@`. |
| 2026-10-18 | architect, core-engineer, connector-engineer, qa | Publish the `pleno-dlp.crash/v1` crash-report schema; assert the Go `crash.Report` struct and the vendored `plenoai.com` relay `validate()` against it so field drift fails CI on either side. |
| 2026-10-18 | connector-engineer, core-engineer, qa | Attribute git findings to `Data[0]`: the go-git fallback emits one segment per added hunk with the leading-context line, native `beginAddedLine`/`nativeAddedHunks` follow the same rule, and the `Line`-means-`Data[0]` contract is documented on the line-bearing metadata structs with a shared engine contract test. |
| 2026-10-18 | core-engineer | Fold local `--crash-report` into the shared `pkg/telemetry/crash` report schema and redactor (`kind: crash`, canonical `Encode`); the file is byte-identical to `telemetry show-last` and the private struct is gone (#559, #586). |
| 2026-10-18 | core-engineer, qa | Add local-only `--crash-report <path>`; record flags given before the subcommand in crash invocation descriptions (#516); build the git-hook end-to-end test binary once per package in `TestMain`. |
| 2026-10-18 | Claude, core-engineer | Add opt-in anonymized crash telemetry (`pleno-dlp telemetry`, supervisor re-exec, relay at crash.plenoai.com) and a native git pre-commit target (`hooks install|print|run git`) that delegates to `protect`; protect, the git hook, and the cursor hook now share one staged-diff transform. |
| 2026-09-22 | Codex, core-engineer, qa | Reuse decoder scan scratch across sequential passes; allocate decode buffers and compile line-detector regexps only after eligible content is found. |
| 2026-09-22 | connector-engineer, qa | Read filesystem inputs larger than 512 KiB on demand to avoid retaining medium file bodies in queued chunks. |
| 2026-09-22 | Codex, connector-engineer, qa | Preserve ordered GitHub sink errors across cancellation branches while retaining caller cancellation and deadline errors. |
| 2026-09-22 | architect, core-engineer, detector-engineer, connector-engineer | Build compact keyword DFA tables without temporary trie maps, borrow buffered archive roots, preallocate bounded gzip bodies, and reject impossible detector candidates while preserving match alignment. |
| 2026-09-22 | architect, core-engineer, detector-engineer, connector-engineer, qa | Stream large bodies, batch finding-span searches, reduce archive buffers, and preserve source errors and checkpoints; source consumers must handle optional `Chunk.Open` payloads. |
| 2026-09-22 | Codex, architect | Moved benchmark tooling and research to the private pleno-dlp-reports repository; product builds and tests remain here. |
| 2026-09-22 | Devin, Codex, core-engineer, qa | Resolve streamed Raw positions with bounded indexes built for dense groups and lazy prefix observation; preserve earliest spans, line numbers, cancellation, and read errors. |
| 2026-09-22 | Devin, connector-engineer, qa | Open worktreeConfig repositories and linked worktrees without modifying repository config; continue rejecting unknown extensions. |
| 2026-09-22 | Devin, connector-engineer, Codex, qa | Stream retained content and merge resolutions in existing partial clones; keep incomplete coverage from advancing checkpoints. GitHub mirrors remain complete while #378 transfer and scale acceptance is pending. |
| 2026-10-18 | core-engineer, qa | Add `engine.ScanBytes`/`ScanBytesWithDetectors`, an offline in-memory scan that returns detector results through the standard engine pipeline with `NoVerify` forced, so crash telemetry and git hooks no longer re-implement the keyword prefilter and detector iteration. |
