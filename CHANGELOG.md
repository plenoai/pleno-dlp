# Changelog

User-visible changes for **pleno-dlp**. Keep this file short: release
notes belong here; detector-by-detector research, benchmark logs, and
implementation notes belong under `docs/`.

Releases are tag-driven. A `vX.Y.Z` tag runs GoReleaser trusted
publishing, archives, SLSA provenance, and SBOM generation.

## [Unreleased]

### Added

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

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.53.0...HEAD
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
