# Changelog

All notable changes follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.7.0] - 2026-05-08

### Changed

- **Vendored ``saas-retriever``**. Up to 0.6.0 we depended on the
  separate ``saas-retriever`` PyPI package; from 0.7.0 the same source
  ships inside this wheel as a sibling top-level package called
  ``saas_retriever``. Imports such as ``from saas_retriever import
  Connector`` keep working unchanged — the only difference is that
  ``pip install pleno-dlp`` no longer pulls a second distribution.
- The ``saas-retriever`` console script is exported by this package so
  the standalone CLI remains available (``saas-retriever list-kinds``,
  ``saas-retriever pull github --owner …``).
- ``saas_retriever`` is now type-checked together with ``pleno_dlp``.
  The previous ``[[tool.mypy.overrides]]`` block that suppressed missing
  imports for ``saas_retriever.*`` has been removed; mypy strict now
  validates both packages end-to-end.

### Removed

- Runtime dependency on ``saas-retriever`` from PyPI. ``httpx``, which
  used to come transitively from saas-retriever, is still listed as a
  direct dependency.

## [0.5.0] - 2026-05-07

### Changed

- **Rebrand**: ``pleno-secret-scanner`` → ``pleno-dlp``. The package is a
  unified DLP scanner now: secret detection (trufflehog / gitleaks /
  native) plus PII detection. The previous PyPI name remains in
  the registry as a historical artifact; new releases publish under
  ``pleno-dlp``. CLI entry point is also ``pleno-dlp``.
- Repository renamed to ``plenoai/pleno-dlp``. GitHub redirects the
  old name; the canonical URL is ``github.com/plenoai/pleno-dlp``.

### Added

- ``pii`` backend — delegates to
  [pleno-anonymize](https://github.com/plenoai/pleno-anonymize)'s
  ``POST /api/analyze`` endpoint. Configure the server URL via
  ``--pii-base-url`` (default ``http://127.0.0.1:8000``) and the
  language hint via ``--pii-language`` (``ja`` or ``en``). Findings
  reuse the existing ``Finding`` shape with ``finding_class="pii"``,
  ``rule_id`` set to the Presidio entity type (``EMAIL_ADDRESS``,
  ``PERSON``, ``JP_MY_NUMBER``, ...), and ``score`` populated from the
  recognizer confidence. ``finding_class="secret"`` is the default so
  every existing secret backend keeps emitting the previous shape.
- ``Finding.score`` and ``Finding.finding_class`` fields. Sinks are
  free to ignore them (back-compat); they round-trip through every
  backend factory and through every output format.

## [0.4.0] - 2026-05-06

### Changed

- **API-only collection**: switched from ``saas-scraper`` (browser /
  Playwright) to [``saas-retriever``](https://pypi.org/project/saas-retriever/)
  (REST API). No more Chromium dependency, no more SAML SSO race;
  authentication is a token via ``--token``, ``GITHUB_TOKEN`` env var,
  or ``gh auth token``.
- ``scan`` CLI no longer takes ``--workspace`` / ``--project`` /
  ``--headed`` / ``--profile-dir`` (browser-only knobs). New
  ``--token`` and ``--include-archived`` reflect the API surface.
- ``scan github --owner <org>`` (no ``--repo``) now performs an
  **org-wide enumeration** by default — every repo under the org is
  walked. Pair with ``--include-archived`` if archived repos matter.
- Default ``--resource`` set is now **code + issues + prs** (was
  ``code`` only). Override with explicit ``--resource`` flags to narrow.

### Removed

- Dependency on ``saas-scraper``. Uninstall it after upgrading: it has
  no remaining consumers.
- Slack / Jira / Confluence / Notion / GitLab / Bitbucket connectors
  (browser-driven). Each returns later as a standalone API connector
  in saas-retriever.

## [0.3.0] - 2026-05-06

### Added

- ``scan`` CLI gains ``--resource`` (repeatable) for the GitHub
  connector. Pass ``--resource code --resource issues --resource prs``
  to scan all three (saas-scraper 0.5.0+). Other connectors ignore the
  flag; the supported-kwargs filter strips it before construction.
- `examples/pleno_anonymize_bridge.py` — adapter wrapping any
  ``saas_scraper.Connector`` as a
  ``pleno_pii_scanner.sources.base.SourceConnector``. Demonstrates that
  the two pipelines share the Document protocol; tests round-trip every
  field. Skipped when ``pleno-pii-scanner`` isn't installed.

### Changed

- Bumped ``saas-scraper`` floor to ``>=0.5.0`` for GitHub issue / PR
  scrape support.

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
- `pleno-dlp` Typer CLI: `scan <connector>`,
  `list-connectors`, `list-backends`, `version`. `scan` exit code 1 on
  any finding, 0 on clean — convenient for CI gating.
- GitHub Actions: ruff + mypy + pytest matrix on Python 3.12 / 3.13;
  tag-pushed PyPI trusted publishing via `pypa/gh-action-pypi-publish`.

[0.5.0]: https://github.com/plenoai/pleno-dlp/releases/tag/py-v0.5.0
[0.4.0]: https://github.com/plenoai/pleno-dlp/releases/tag/py-v0.4.0
[0.3.0]: https://github.com/plenoai/pleno-dlp/releases/tag/py-v0.3.0
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/py-v0.2.0
