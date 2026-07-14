# Changelog

User-visible changes for **pleno-dlp**, one line per change. Rationale,
benchmarks, and implementation notes belong in the PR or under `docs/`.

Releases are tag-driven. A `vX.Y.Z` tag runs GoReleaser trusted
publishing, archives, SLSA provenance, and SBOM generation.

## [Unreleased]

### Added

- GitHub scans can bound each repository history walk with
  `--repo-walk-timeout`; every scan command can write a `--cpu-profile`.

### Changed

- Default Git history scans stream bounded native Git patches instead of
  repeatedly decoding and diffing trees through go-git.
- GitHub history scans use complete, self-contained mirror clones so an
  offline walk cannot fail on a blob omitted by partial clone. Histories with
  blobs over 50 MiB can use more clone bandwidth and disk than v0.63.0; bounded
  transfer without authenticated lazy fetch is tracked in #378.
- Degraded incremental scans retain completed unit checkpoints without
  promoting the whole-resource fingerprint, so failed units are retried.

## [v0.62.0] - 2026-07-12

### Fixed

- **Security:** claude-code PreToolUse hook scans `Edit`/`MultiEdit`
  tool calls, not only `Write` (#357).
- **Security:** `revoke` uses a real TTY check; redirected stdin no
  longer bypasses `PLENO_DLP_ALLOW_REVOKE=1` (#359).
- Slack connector no longer doubles the API path to `/api/api/...` (#358).
- Finding line numbers reflect the secret's actual line instead of
  always 1, across all output formats (#360).
- `--pii-engine=openai-pf` bootstraps again; upstream dependency is
  declared under its real distribution name `opf` (#362).
- Documented GitHub Action pin updated to an existing tag (#361).
- `action-test` smoke scans a dedicated secret-free fixture
  (`.github/action-smoke/`) instead of `docs/` and asserts zero findings.

## [v0.61.0] - 2026-07-10

### Added

- GitHub scans can opt into wikis, gists and gist comments, issue/PR
  titles and bodies, commit metadata, Git notes, and bounded
  Git-history archive/binary content.
- Repository-level concurrency, scope controls, deterministic
  source-unit output, and v3 incremental-state retention for large
  organization scans.

### Changed

- Large Git modifications and new blobs stream in bounded chunks.
- Partial source/detector/archive failures return structured
  degraded-coverage errors after preserving findings and checkpoints.
- Test and tag-release workflows share the same gates.

### Security

- Hardened archive limits, decompression cancellation, GitHub
  redirect/TLS/token-refresh boundaries, and cross-worker backpressure.

## [v0.60.0] - 2026-07-10

### Changed

- **BREAKING:** `--fail-on` defaults to `high` instead of `any` for
  `scan` and `protect`. Named-detector and verified/critical findings
  still gate; add `--fail-on any` to restore the old behavior. See
  [`docs/recipes/staged-rollout.md`](docs/recipes/staged-rollout.md). (#250)
- GitHub history scans skip repos with no pushes since the last run (#252),
  log per-repo progress and a 60s heartbeat, and log/cap rate-limit waits.
- GitHub incremental fingerprint digests repo-list metadata only; with
  `--include-comments` the whole-org skip fast-path is disabled.
- `--format json` streams findings instead of buffering the full array.
- Per-repo scan failures keep previous incremental state; state flushes
  stream per repo and are throttled to one per 30s, so a crash resumes
  from the last flushed repo.

### Added

- `pleno-dlp hooks install claude-code|cursor` wires the scanner into
  editor/agent hooks; idempotent, reversible via `hooks uninstall`. See
  [`docs/hooks.md`](docs/hooks.md). (#303)
- `--no-verify` scan flag skips all network verification for fast
  offline scans (#303).
- Official cosign-verified GitHub Action `uses: plenoai/pleno-dlp@vX.Y.Z`
  with a `sarif-file` output (#301).
- Homebrew tap: `brew install plenoai/tap/pleno-dlp` (#302).
- Versioned audit trail (schema v1) for every revoke attempt via
  `--audit-trail`; records carry a sha256 hash, never the raw secret. See
  [`docs/audit-trail-schema.md`](docs/audit-trail-schema.md). (#304)
- `scan --revoke-spool` / `revoke --revoke-from-spool` decouple detection
  from revocation. See `docs/revoke-support.md`.
- Expanded `docs/comparison.md` with real-world evaluation against
  trufflehog 3.95.5 and gitleaks 8.30.1.

### Fixed

- GitHub REST client retries transient GET 5xx and body-read errors.
- Incremental GitHub fingerprint: per-repo failures and empty repos no
  longer abort the whole org scan.

## [0.53.0] - 2026-06-10

### Added

- Added `docs/comparison.md`: measured recall, false-positive, and
  capability comparison against trufflehog and gitleaks.

### Fixed

- Fixed `--pii-engine=anonymize` readiness failure from renamed
  upstream NER model wheels.
- Fixed warm-start PII engine breakage: NER wheels are reinstalled
  unconditionally after `uv sync` prunes them.

## [0.52.0] - 2026-06-09

### Added

- Added GitHub App authentication with automatic installation token
  refresh for long-running scans.

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

- Added migration-friendly verified scans, including verified-only scan
  output and GitHub scan fingerprinting.
- Added GitHub PAT revocation support.
- Added S3 and SQL dump source connectors.
- Added SIEM connectors for Datadog, Splunk, BigQuery, and Redash.
- Added PIIDB cross-finding candidate detection and severity escalation.
- Added context-extraction verification to 10 Shai-Hulud-targeted detectors.

### Changed

- Enabled required status checks and build-provenance attestation.

## [0.46.0] - 2026-06-07

### Fixed

- Dedup and path allowlists now use connector-specific location keys for
  GitLab, Confluence, Jira, Notion, and Bitbucket findings.
- Notion connector recreates the request body on 429 retries.
- SARIF `semanticVersion` reflects the actual binary version.
- Incremental scan fingerprint includes `tool_version`, so tool upgrades
  invalidate stale results.

## [0.45.0] - 2026-05-31

### Added

- Added the `openai/privacy-filter` PII engine via
  `--pii-engine=openai-pf` and the `pleno-dlp openai-pf-server`
  supervisor.
- Added `--pii-engine-device` for `openai-pf` device selection.
- Added SARIF per-result `security-severity=9.5` for findings tagged
  with blast-radius metadata.

### Changed

- `--pii-engine-ready-timeout` and `--pii-engine-cmd` now default to
  engine-defined values.
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
[v0.61.0]: https://github.com/plenoai/pleno-dlp/compare/v0.60.0...v0.61.0
[v0.60.0]: https://github.com/plenoai/pleno-dlp/compare/v0.53.0...v0.60.0
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
