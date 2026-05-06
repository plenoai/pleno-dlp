# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `examples/pleno_anonymize_bridge.py` — adapter wrapping any
  ``saas_scraper.Connector`` as a
  ``pleno_pii_scanner.sources.base.SourceConnector``. Demonstrates that
  the two pipelines share the Document protocol; tests round-trip every
  field. Skipped when ``pleno-pii-scanner`` isn't installed.

## [0.2.0] - 2026-05-06

Initial Python release. Tag pattern is `py-vX.Y.Z` to coexist with the
legacy Go binary's `vX.Y.Z` tags in the same repo.

### Added

- `Backend` protocol + three implementations (`native`, `trufflehog`,
  `gitleaks`). `native` ships AWS, GitHub PAT/fine-grained, Slack
  bot/user, OpenAI, and Anthropic regex rules. `trufflehog` and
  `gitleaks` shell out to the respective CLIs and parse JSON output.
- `Finding` dataclass — wire-format struct shared across backends, with
  source-ref fields aligned with `saas_scraper.DocumentRef`.
- `Pipeline` — wires a saas-scraper Connector to a Backend and emits
  Findings.
- Output sinks: `json` (NDJSON), `sarif` (SARIF 2.1.0), `table` (rich).
- `pleno-secret-scanner` Typer CLI: `scan <connector>`,
  `list-connectors`, `list-backends`, `version`. `scan` exit code 1 on
  any finding, 0 on clean — convenient for CI gating.
- GitHub Actions: ruff + mypy + pytest matrix on Python 3.12 / 3.13;
  tag-pushed PyPI trusted publishing via `pypa/gh-action-pypi-publish`.

[0.2.0]: https://github.com/plenoai/pleno-secret-scanner/releases/tag/py-v0.2.0
