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
| 2026-09-22 | connector-engineer, qa | Read filesystem inputs larger than 512 KiB on demand to avoid retaining medium file bodies in queued chunks. |
| 2026-09-22 | Codex, connector-engineer, qa | Preserve ordered GitHub sink errors across cancellation branches while retaining caller cancellation and deadline errors. |
| 2026-09-22 | architect, core-engineer, detector-engineer, connector-engineer | Build compact keyword DFA tables without temporary trie maps, borrow buffered archive roots, preallocate bounded gzip bodies, and reject impossible detector candidates while preserving match alignment. |
| 2026-09-22 | architect, core-engineer, detector-engineer, connector-engineer, qa | Stream large bodies, batch finding-span searches, reduce archive buffers, and preserve source errors and checkpoints; source consumers must handle optional `Chunk.Open` payloads. |
| 2026-09-22 | Codex, architect | Moved benchmark tooling and research to the private pleno-dlp-reports repository; product builds and tests remain here. |
| 2026-09-22 | Devin | Engine raw-position resolution: multi-byte prefix candidate filtering (#436) and per-window occurrence hints to bound re-scan (#437). |
| 2026-09-22 | Devin | Git source opens repositories with extensions.worktreeConfig and linked worktrees without mutating their config (#380); unknown extensions remain rejected. |
| 2026-09-22 | Devin | GitHub history clones filter blobs above the artifact ceiling and walk promisor clones offline via tree-level diff enumeration plus bounded cat-file batches; omitted blobs are intentional skips, not walk failures (#378). |
| 2026-09-22 | Devin | Offline history walk rework: streamed bounded blob emission replaces whole-blob reads, clone config is parsed for promisor/filter values, empty commits and all merge-parent blobs are covered, and missing in-scope objects degrade coverage instead of checkpointing (#378); shared-prefix raw lookups escalate to a lazily built per-prefix position index so resolution reads stay flat across batches (#437). |
| 2026-09-22 | Devin | Round-2 semantics: promisor detection reuses go-git's config parser with per-remote association; any missing blob whose content cannot be ruled out of scope degrades coverage with the checkpoint retained (no size-based omissions; deletions and excluded paths still skip); diff-tree runs with --always so empty commits cannot deadlock the bounded queue; merge commits process in bounded batches; raw-position indexes for all saturated prefixes build in one shared input pass and store short content samples so verification needs no per-batch rescans; short candidate reads propagate io.ErrUnexpectedEOF (#378, #437, #436). |
| 2026-09-22 | Devin | Round-3 root causes: merge commits feed diff-tree in lockstep within the bounded queue (no deadlock, merges still honor SkipMergeCommits/TrufflehogCompatible); locally present text blobs of any size stream in chunk windows on both the offline and go-git whole-file-add paths, matching the native appendFile policy; engine prefix position indexes share a total-position and sample-byte budget across cached and in-flight builds with fallback to the bounded shared scan when exhausted (#378, #437). |
