# Changelog

User-visible changes for **pleno-dlp**. Keep this file short: release
notes belong here; detector-by-detector research, benchmark logs, and
implementation notes belong under `docs/`.

Releases are tag-driven. A `vX.Y.Z` tag runs GoReleaser trusted
publishing, archives, SLSA provenance, and SBOM generation.

## [Unreleased]

## [v0.62.0] - 2026-07-12

### Fixed

- **Security:** the `hooks install claude-code` PreToolUse hook now scans
  `Edit`/`MultiEdit` tool calls, not only `Write`. It previously read only
  `tool_input.content`, so secrets introduced through an Edit's `new_string`
  were never scanned and passed through unblocked (#357).
- **Security:** `revoke` no longer treats `</dev/null` as an interactive
  terminal. The non-interactive guard now uses a real TTY check, so an
  irreversible revoke cannot run without `PLENO_DLP_ALLOW_REVOKE=1` when stdin
  is redirected from a device file (#359).
- The Slack connector no longer doubles the API path to `/api/api/...`; `scan
  slack` and `verify slack` now reach the real Slack Web API (#358).
- Finding line numbers now reflect where the secret sits in the file instead
  of always reporting line 1, across table, JSON, SARIF, and git-history
  output (#360).
- `--pii-engine=openai-pf` bootstraps again: the upstream dependency is
  declared under its actual distribution name `opf`, which uv/pip requires to
  match (#362).
- Documented GitHub Action usage pins `plenoai/pleno-dlp@v0.61.0`; the prior
  `@v0.59.0` predated `action.yml` and resolved to a 404 (#361).
- The `action-test` smoke workflow now scans a dedicated secret-free fixture
  (`.github/action-smoke/`) instead of `docs/`. `docs/` documents a secrets
  scanner and contains secret-shaped strings by design (detector key-format
  tables, an example audit-trail record), so `--fail-on high` failed the
  smoke job; because the workflow only re-ran on `action.yml` changes, the
  contamination that landed with the audit-trail schema doc stayed latent
  until an unrelated `action.yml` edit surfaced it. The SARIF check now also
  asserts zero findings so fixture contamination fails loudly.

## [v0.61.0] - 2026-07-10

### Added

- GitHub scans can opt into repository wikis, explicit or authenticated-user
  gists, gist comments, issue and pull-request titles/bodies, commit metadata,
  Git notes, and bounded Git-history archive/binary content.
- Repository-level concurrency, repository scope controls, collaboration
  timeframes, deterministic source-unit output, and v3 incremental-state
  retention make large organization scans bounded and resumable.

### Changed

- Large Git modifications and newly added blobs are streamed in bounded chunks
  instead of being silently skipped or emitted as one large allocation.
- Partial source, detector, archive, and Git-history failures now return
  structured degraded-coverage errors after preserving successful findings and
  safe incremental checkpoints.
- Test and tag-release workflows share the same race, detector-unit,
  source-prefilter, and CLI E2E gates.

### Security

- Hardened archive limits, traversal and decompression cancellation; GitHub
  redirect, pagination, clone-origin, TLS and token-refresh boundaries; and
  cross-worker artifact/rate-limit backpressure.

## [v0.60.0] - 2026-07-10

### Changed

- **BREAKING: `--fail-on` now defaults to `high`, not `any`** (`scan`
  and `protect`). Previously the default gated CI on *any* finding of
  any severity, so a single Medium-or-below hit (generic high-entropy
  string, JWT, PEM blob, PII) broke a first-time adopter's pipeline
  before they had a chance to triage anything. The new default still
  fails the build on every named-secret detector hit and every
  verified/critical finding — it only stops treating Medium-and-below
  noise as a hard gate. Findings below the gate still print and still
  count; the end-of-scan summary now says so explicitly and names the
  escape hatch:
  `exit gate: --fail-on=high (N low/medium finding(s) did not affect exit code; use --fail-on=any to block on all)`.
  Pipelines that relied on the old enforce-everything behavior should
  add `--fail-on any` explicitly. See
  [`docs/output-and-gating.md`](docs/output-and-gating.md) and the new
  [`docs/recipes/staged-rollout.md`](docs/recipes/staged-rollout.md)
  for the recommended audit → gate → ratchet sequence. (#250)

- **GitHub history scans skip repos with no pushes since the last run**.
  Per-repo incremental state now records `pushed_at` as observed at
  enumeration time; a rerun whose enumeration reports the same value
  skips the clone and walk outright and carries the state forward
  (`--include-comments` still runs for skipped repos — comments move
  without touching `pushed_at`). On a large org scanned daily this
  removes the clone traffic for the majority of repos, which typically
  saw no pushes. (#252)

- **GitHub history scans emit a per-repo heartbeat**. While one repo is
  being cloned or walked, a stderr line
  (`github: heartbeat owner/repo phase=… chunks=… heap=… sys=… elapsed=…`)
  fires every 60s, so a multi-hour walk of a huge monorepo is
  distinguishable from a hang and memory pressure is visible before an
  OOM kill. Clone transfer progress is logged at the same cadence, and
  clone/walk/repo/org completion each log a duration. The per-repo scan
  line now includes the repo's on-disk size from the repo listing.

- **GitHub incremental fingerprint is now repo-list metadata only**. The
  whole-resource fingerprint used for the "nothing changed, skip the
  scan" fast-path now digests the repo list (name, default branch,
  `pushed_at`, `updated_at`) instead of advertising every repo's refs
  and paging through every issue/PR comment. On large orgs the old
  fingerprint pass duplicated the scan's entire REST cost and could
  spend hours against an exhausted rate limit before the scan started.
  With `--include-comments` no cheap whole-org fingerprint exists
  (comment edits don't surface in repo metadata), so the source now
  opts out of the skip fast-path entirely (`ResourceFingerprint`
  returns `""`); per-repo incremental state still keeps reruns cheap.
- **JSON output streams findings**. `--format json` used to buffer every
  finding in memory and encode one array at `Close`; each finding is now
  written as it is emitted (same JSON array shape on the wire), keeping
  the sink O(1) in memory on long org scans.
- **GitHub rate-limit waits are logged and capped**. Retry sleeps
  (rate-limit backoff, GET 5xx backoff, shared-bucket reset waits over
  30s) now emit a stderr line with the wait duration and attempt count —
  multi-hour scans previously slept in total silence and were
  indistinguishable from a hang. A single backoff sleep is capped at 65
  minutes (an honest `Retry-After`/`X-RateLimit-Reset` never legitimately
  exceeds the hourly reset window; anything larger is clock skew or a
  bogus header).
- **GitHub org scan logs per-repo progress**. `scanGitHubHistory` prints
  `github: scan [i/N] owner/repo` per repo and a `WARN` line when a
  repo's code or comment pass is skipped after errors.
- **Per-repo scan failures keep the previous incremental state**. A repo
  whose clone/walk fails carries its previous state forward (instead of
  dropping it and forcing a full rescan next run); a repo whose comment
  pass fails keeps the new ref heads plus the previous comment cursors.
- **Incremental state flushes are throttled to one per 30s**. Each flush
  marshals the whole org state, so flushing after every repo cost
  O(N²) allocations over a long run; a crash now loses at most 30s of
  progress instead.

### Added

- **`pleno-dlp hooks install claude-code|cursor`**. One command wires the
  scanner into an editor/agent's own hook mechanism: claude-code gets a
  `PreToolUse` Edit|Write hook (blocks on a finding via exit 2), cursor a
  `beforeShellExecution` hook gating `git commit`. Installs are idempotent
  and reversible with `hooks uninstall`. Hooks use the new fast
  `--no-verify` stdin path (below); measured hook latency ~23 ms median is
  published in [`docs/hooks.md`](docs/hooks.md). (#303)
- **`--no-verify` scan flag**. Skips every detector's network `Verify()`
  round-trip at the engine level so a scan runs fully offline and fast,
  meant for latency-sensitive callers like pre-commit/agent hooks. Every
  finding's verdict is `unverified` (not `indeterminate`). Mutually
  exclusive with `--only-verified`. (#303)
- **Official cosign-verified GitHub Action**. A one-line
  `uses: plenoai/pleno-dlp@vX.Y.Z` step downloads the release archive,
  cosign-verifies `checksums.txt` against the release workflow's keyless
  Sigstore identity, runs a scan, and exposes a `sarif-file` output for
  `github/codeql-action/upload-sarif`. See
  [`docs/output-and-gating.md`](docs/output-and-gating.md#github-action). (#301)
- **Homebrew tap**. `brew install plenoai/tap/pleno-dlp` installs a pinned
  binary; the formula is published to `plenoai/homebrew-tap` automatically
  by GoReleaser on tag push. (#302)
- **Versioned audit trail (schema v1) for every revoke attempt**. New
  `pkg/audit` package defines `audit.Record` (JSON Lines,
  `schema_version: "1"`) and `Record.ToSARIFProperties()`, the matching
  SARIF properties-bag representation. All three revoke code paths —
  `revoke --detector/--secret`, `revoke --revoke-from-spool`, and
  `scan --revoke-on-verified` — now emit one record per attempt via the
  new `--audit-trail <path>` flag (falls back to stderr when omitted;
  the trail is never silently dropped). Records never carry the raw
  secret — only a sha256 hash and the existing prefix+ellipsis
  redaction. `scan --revoke-on-verified` findings additionally carry an
  `audit_trail_id` key in `extra_data`/SARIF `properties` that
  correlates back to the full trail record. See
  [`docs/audit-trail-schema.md`](docs/audit-trail-schema.md). (#304)

- **incremental scan: streaming per-unit state flush**. New optional
  `sources.IncrementalFlushSource` interface lets a connector hand the
  cmd layer a partial state snapshot after each processed unit (per-repo
  for GitHub). The cmd `scan` command wires a flush closure that
  persists the state file via temp-file + atomic rename, so a scan that
  crashes, is OOM-killed, or exits non-zero mid-org keeps the work done
  so far. The next run resumes from the last flushed repo. The GitHub
  connector flushes inside `scanGitHubHistory` after each
  `nextState.Repos[repoKey] = nextRepo`.

### Fixed

- **incremental GitHub fingerprint: skip per-repo failure, treat as changed**.
  When a single repo's fingerprint walk exhausts retries (rate-limit
  exhaustion, persistent 5xx, body read err) the org loop no longer aborts
  the whole scan. A `fingerprint-failed` seed is mixed into the running
  hash so the failed repo's fingerprint guarantees diff from the previous
  scan — incremental skips disabled for it, full scan on next run (safe
  side). A `WARN` line is logged to stderr per skipped repo.
- **GitHub REST client: retry transient body-read errors in `getJSON`**.
  After `c.do()` returns 200, body reading can still fail with HTTP/2
  `stream error: ... CANCEL`, `GOAWAY`, unexpected EOF, or connection
  reset — typically from intermediate proxies under load on multi-hour
  scans. The decoded page is now retried with exponential backoff (up to
  5 attempts, 1 min cap). Non-transient JSON syntax errors are surfaced
  immediately as before.
- **GitHub REST client: retry transient 5xx on GET**. `c.do()` now retries
  HTTP 502/503/504 for idempotent GETs with the same exponential backoff
  used for rate-limit waits (up to 5 attempts, max 1 min between). This
  prevents a single Bad Gateway during a multi-hour org fingerprint walk
  from aborting the entire scan. POST/PATCH/DELETE are unaffected.
- **incremental GitHub fingerprint**: skip empty repos (0 commits) instead
  of failing the whole org scan. go-git's `transport.ErrEmptyRemoteRepository`
  is now treated as "no refs to fingerprint" and the loop continues to the
  next repo, fixing
  `incremental: fingerprint github source: github: list remote refs for …: remote repository is empty`.

### Added

- **scan `--revoke-spool` / revoke `--revoke-from-spool`**: decouple
  detection from revocation. Scan writes verified findings to a JSONL
  spool file (mode 0600) gated by `PLENO_DLP_ALLOW_RAW_EXPORT=1`; a
  later `revoke --revoke-from-spool` consumes the file and dispatches
  each line to the per-detector Revoker. Mutually exclusive with
  `--revoke-on-verified`. See `docs/revoke-support.md`.
- Expanded `docs/comparison.md` with real-world evaluation: labeled
  corpora (leaky-repo, terragoat, OWASP Juice Shop), an adjudicated
  popular-OSS noise sweep, git-history behavior, and verification
  triage value. All numbers re-pinned to the released v0.53.0 binary
  and current upstream trufflehog 3.95.5 / gitleaks 8.30.1.

## [0.53.0] - 2026-06-10

### Added

- Added `docs/comparison.md`: measured recall, false-positive, and
  capability comparison against trufflehog 3.95.5 and gitleaks 8.30.1.

### Fixed

- Fixed `--pii-engine=anonymize` failing readiness with spaCy E050:
  the NER model wheels were renamed upstream (`ja_ner_ja` →
  `pleno_anonymize_ja`, `en_ner_en` → `pleno_anonymize_en`) and the
  bootstrap still installed the old names.
- Fixed warm-start PII engine breakage with `--no-fetch` or a local
  `--source`: `uv sync` prunes the NER wheels (outside `uv.lock`) on
  every run, but reinstall only happened on fresh checkouts. Wheels
  are now reinstalled unconditionally (idempotent).

## [0.52.0] - 2026-06-09

### Added

- Added GitHub App authentication for GitHub scans and verification,
  including automatic installation token refresh for long-running scans.

## [0.51.0] - 2026-06-09

### Added

- Made verification the default scan behavior.
- Added incremental scanning for changed source objects.

## [0.50.0] - 2026-06-08

### Added

- Added incremental scanning for changed S3 objects.

## [0.49.0] - 2026-06-08

### Added

- Added incremental scanning for changed GitHub resources.

## [0.48.0] - 2026-06-08

### Fixed

- Emitted GitHub source links in JSON output.

## [0.47.0] - 2026-06-08

### Added

- Added migration-friendly verified scans, including verified-only scan output
  and GitHub scan fingerprinting.
- Added GitHub PAT revocation support.
- Added S3 and SQL dump source connectors.
- Added SIEM connectors for Datadog, Splunk, BigQuery, and Redash.
- Added PIIDB cross-finding candidate detection and severity escalation.
- Added context-extraction verification to 10 Shai-Hulud-targeted detectors.

### Changed

- Enabled required status checks and build-provenance attestation.

## [0.46.0] - 2026-06-07

### Fixed

- **dedup + allowlist**: `locationOf()` and `findingPath()` now handle
  GitLab, Confluence, Jira, Notion, and Bitbucket findings. Previously
  all findings from these sources resolved to the same location key,
  causing deduplification to suppress every occurrence after the first
  when the same secret appeared in multiple pages or repositories.
  Path-based allowlist rules were also silently ignored for these
  connectors. Both functions now emit stable, connector-specific keys.
- **Notion connector**: `do()` retry logic recreates the request body
  on each attempt. The previous implementation reused a consumed
  `io.Reader`, sending an empty POST body on 429 retries and receiving
  400 responses instead of retrying successfully.
- **SARIF output**: `semanticVersion` in the SARIF `tool.driver` block
  now reflects the actual binary version injected by the linker. It was
  previously hardcoded to `"0.1.0"`, breaking version-aware diffing in
  GitHub Code Scanning.
- **Incremental scan**: `scannerFingerprint` now includes `tool_version`
  so incremental cache invalidates when the binary version changes. Tool
  upgrades that improve detector regexes no longer return stale
  false-clean results for unchanged resources.

## [0.45.0] - 2026-05-31

### Added

- Added the `openai/privacy-filter` PII engine via
  `--pii-engine=openai-pf` and the `pleno-dlp openai-pf-server`
  supervisor.
- Added `--pii-engine-device` for `openai-pf` device selection.
- Added SARIF per-result `security-severity=9.5` for findings tagged
  with blast-radius metadata.

### Changed

- `--pii-engine-ready-timeout` now defaults to `0`, meaning
  engine-defined: 60s for `anonymize`, 300s for `openai-pf`.
- `--pii-engine-cmd` now follows the selected engine when the operator
  does not set it explicitly.
- Verify coverage is now `a=540 / b=59 / c=1`; query live builds with
  `pleno-dlp detectors list --verify-status`.

## [0.44.0] - 2026-05-12

- Added the Aho-Corasick keyword prefilter for detector dispatch.

## [0.43.0] - 2026-05-12

### Added

- Added JWT claim-aware severity and metadata enrichment.
- Added blast-radius metadata for high-impact verified credentials
  across cloud, SaaS, and payment providers.
- Added `pleno-dlp scan --blast-radius-only`.

## [0.42.0] - 2026-05-12

### Changed

- Tightened filesystem defaults for common lockfiles, minified bundles,
  source maps, and generated dependency noise.
- Promoted `PrivateKeyPEM` to a verifiable detector by deriving the
  public key fingerprint locally and checking Certificate Transparency.

## [0.41.0] - 2026-05-10

### Changed

- Replaced legacy regex PII detectors with the opt-in
  `PIIAnonymize` engine path.

### Added

- Added `pleno-dlp pii-server` to supervise the pleno-anonymize HTTP
  server through `uv`.

## [0.40.0] - 2026-05-10

### Added

- Added provider-side revocation through `pleno-dlp revoke`.
- Added `scan --revoke-on-verified` and `--revoke-dry-run`.
- Added `detectors list --revoke-support`.

## [0.39.0] - 2026-05-10

### Added

- Added `detectors list --verify-status` and CI drift checks for the
  verify-coverage classification.

## [0.38.0] - 2026-05-10

### Changed

- Migrated SaaS connectors to native Go source adapters.
- Removed the Python package/release path; pleno-dlp ships as a single
  Go binary.

## [0.37.0] - 2026-05-08

- Added the final detector expansion batch that brought the registry to
  600 detector types.

## Earlier Detector Expansion Releases

Versions `0.7.0` through `0.36.0` were rapid detector-expansion
releases. Their durable references are:

- `docs/verify-coverage.md` for verification status.
- `docs/detector-key-formats.md` for key-format research and
  false-positive hardening.
- GitHub Releases for tag-specific generated notes.

## [0.6.0] - 2026-05-08

### Added

- Added pre-commit distribution metadata.
- Added stdin label support to the dedup key.

## [0.5.0] - 2026-05-08

### Added

- Added detector introspection and shell completions.

## [0.4.0] - 2026-05-08

### Added

- Added per-host verify rate limiting via `--verify-rps`.

## [0.3.0] - 2026-05-08

### Added

- Added local git history scanning.
- Added stdin scanning.
- Added custom rule files.

## [0.2.0] - 2026-05-08

### Added

- Added SARIF, table output, severity-based `--fail-on`, filesystem
  include/exclude flags, decoding, archive scanning, and the
  GoReleaser pipeline.

### Changed

- Renamed `pleno-secret-scanner` to `pleno-dlp`.

## [0.1.0] - 2026-05-06

### Added

- Initial CLI with filesystem scanning, core secret detectors, and JSON
  output.

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.62.0...HEAD
[v0.62.0]: https://github.com/plenoai/pleno-dlp/compare/v0.61.0...v0.62.0
[0.53.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.53.0
[0.52.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.52.0
[0.51.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.51.0
[0.50.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.50.0
[0.49.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.49.0
[0.48.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.48.0
[0.47.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.47.0
[0.46.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.46.0
[0.45.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.45.0
[0.44.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.44.0
[0.43.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.43.0
[0.42.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.42.0
[0.41.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.41.0
[0.40.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.40.0
[0.39.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.39.0
[0.38.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.38.0
[0.37.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.37.0
[0.6.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.6.0
[0.5.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.5.0
[0.4.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.4.0
[0.3.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.3.0
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.2.0
[0.1.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.1.0
