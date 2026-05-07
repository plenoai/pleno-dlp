# Changelog

All notable changes to **pleno-dlp** (Go binary). Tracks tag-push
trusted publishing — `vX.Y.Z` tags trigger GoReleaser, archives, SLSA
build provenance, and syft SBOMs. The Python package on PyPI is
versioned independently (`py-vX.Y.Z`).

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Anything merged to `main` since v0.2.0.

## [0.2.0] — 2026-05-08

### Added

- **57 secret detectors** ported from trufflehog's surface, each with
  `Keywords` / `FromData` / `Type` / `Verify`:
  - **Cloud / infra** — AWS, GCP service-account, Azure storage key,
    DigitalOcean, Cloudflare, Heroku, Render, Fly.io, Vercel, Netlify,
    Terraform Cloud, Dropbox
  - **VCS / dev tooling** — GitHub PAT, GitLab PAT, Bitbucket Cloud,
    npm, PyPI, Hugging Face, Postman, Atlassian, Jira, Confluence
  - **AI** — OpenAI, Anthropic, Cohere, Replicate, Mistral, Groq,
    OpenRouter, Together
  - **Comms / SaaS** — Slack bot tokens, Slack webhooks, Discord,
    Twilio, SendGrid, Mailgun, Mailchimp, Brevo, Postmark, Notion,
    Linear, Asana, Mixpanel, Segment, Okta, HubSpot, Intercom,
    Salesforce refresh
  - **Observability** — Datadog, Sentry, New Relic, PagerDuty
  - **Payments / data** — Stripe, Square, PayPal, Plaid,
    MongoDB Atlas
  - **Format-shaped** — JWT, PEM private keys
- **Decoder pipeline** (`pkg/decoder`) — base64 (std + url-safe + raw),
  percent-encoding, hex. Decoded variants are scanned alongside the
  raw chunk; ExtraData["decoded_from"] marks which decode produced
  the hit.
- **Archive walker** (`pkg/archive`) — zip, tar, tar.gz, gzip.
  Recursive expansion with depth cap (4) and per-entry size cap
  (50 MiB) to defuse zip bombs. ExtraData["archive_path"] travels
  with the finding.
- **Custom rule loader** (`pkg/detectors/custom`) — JSON rules with
  `keywords`, `regex`, optional `entropy_min`, `severity`, and
  `verify_url` + `verify_header` (with `{{ .Secret }}` substitution).
- **Severity classification** — `info` / `low` / `medium` / `high` /
  `critical`. Default model: verified ⇒ critical, generic / JWT /
  PEM unverified ⇒ medium, explicit detectors unverified ⇒ high.
  `--fail-on <severity>` gates CI exit code.
- **Allowlist** (`pkg/engine/allowlist.go`) — `--allowlist <path>` and
  auto-discovery of `.pleno-allow.json` from cwd. Match by detector
  type, raw literal, raw regex, and path glob (AND).
- **Git source** (`pkg/sources/git`) — walks a local repository's
  commit history. Flags: `--repo`, `--branch`, `--since`,
  `--max-depth`, `--include`, `--exclude`.
- **Stdin source** (`pkg/sources/stdin`) — `pleno-dlp scan stdin`
  reads a single chunk from `os.Stdin`. `--label` overrides the
  pseudo-path. `--max-bytes` caps buffered input (default 64 MiB).
  TTY guard prevents silent waiting on keyboard input.
- **Filesystem source globs** — `--include`, `--exclude`,
  `--max-size`, `--no-default-excludes`. Default excludes: `.git`,
  `.hg`, `.svn`, `node_modules`, `vendor`, `target`, `dist`,
  `build`, `__pycache__`, `.venv`, `.tox`.
- **SARIF 2.1.0** output now satisfies GitHub Code Scanning ingest
  (rules array, partialFingerprints, semanticVersion, level
  per-severity).
- **JSON / table** outputs render the new severity field plus
  source-specific metadata (file path, repo+commit, stdin label).
- **GoReleaser pipeline** — `-trimpath`, LICENSE + README in
  archives, syft SBOMs, conventional-commit changelog grouping,
  SLSA build provenance via `actions/attest-build-provenance`,
  release attestations via `gh attestation verify`.

### Changed

- `pleno-secret-scanner` rebranded to `pleno-dlp` (unified
  DLP scanner consolidating secrets + PII).

## [0.1.0] — 2026-05-06

### Added

- Initial MVP: filesystem source + 5 detectors (AWS, GitHub PAT,
  Slack bot, OpenAI, Anthropic) + JSON / SARIF / table output +
  cobra `scan` CLI. 51 race-clean tests.

[Unreleased]: https://github.com/plenoai/pleno-dlp/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.2.0
[0.1.0]: https://github.com/plenoai/pleno-dlp/releases/tag/v0.1.0
