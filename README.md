# pleno-dlp

Unified DLP scanner — secrets **and** PII — over filesystem and SaaS content.

Two surfaces in one repo:

- **Python package** (`python/`) — the path forward for SaaS sources.
  Consumes [saas-retriever](https://pypi.org/project/saas-retriever/) for
  API-only content collection (org-wide GitHub today; Slack, Jira,
  Confluence, Notion, GitLab, Bitbucket as upstream connectors land) and
  pluggable detection backends — `trufflehog` / `gitleaks` / `native`
  for secrets, plus `pii` (delegates to
  [pleno-anonymize](https://github.com/plenoai/pleno-anonymize) for PII
  model inference). Tag pattern: `py-vX.Y.Z`. See
  [`python/README.md`](python/README.md).
- **Go binary** (this directory) — filesystem scanner with
  trufflehog-compatible detector interfaces, for local repo scans
  outside the SaaS pipeline. Tag pattern: `vX.Y.Z`.

## Why this rebrand

`pleno-secret-scanner` (the previous name) covered secrets only.
`pleno-dlp` consolidates the secret pipeline with the PII pipeline that
previously lived inside `pleno-anonymize`'s source connector wheels —
one tool, one finding shape, one CLI for both classes of leaks.
`pleno-anonymize` retains the PII filter API + Model only (the
inference backbone) and stops shipping per-SaaS source connectors.

## Go binary scope

- **Detectors** — port of trufflehog's `Detector` interface (`Keywords`,
  `FromData`, `Type`, `Verify`). MVP: AWS, GitHub PAT, Slack bot, OpenAI,
  Anthropic — each with `Verify()`. Roadmap covers GCP/Azure, GitLab,
  Stripe, Notion, JWT, generic high-entropy.
- **Sources** — reimplemented connector layer (`pkg/sources/`) covering
  filesystem only on the Go side. SaaS sources live in the Python
  package via `saas-retriever`.
- **Engine** — concurrent scan loop, dedup, false-positive filter,
  output (JSON / SARIF / table).
- **CLI** — cobra-based: `pleno-dlp scan <path> [--format json|sarif|table] [--verify] [--concurrency N]`.

## Install

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest
```

Or grab a pre-built archive from
[releases](https://github.com/plenoai/pleno-dlp/releases) (linux / darwin
/ windows × amd64 / arm64).

## Usage

```sh
pleno-dlp scan ./path/to/repo
pleno-dlp scan ./path --format sarif > findings.sarif
pleno-dlp scan ./path --verify           # confirms candidates against upstream APIs
```

Exit code is `1` when at least one finding is emitted, `0` otherwise.

## Status

| Area | State |
|---|---|
| Secret detectors | AWS, GitHub PAT, Slack bot token, OpenAI, Anthropic — each with `Verify()` |
| PII detectors | via `pleno-dlp` Python `pii` backend → pleno-anonymize model API |
| Sources (Go) | filesystem (recursive walk, skips binary / oversize / symlinks) |
| Sources (Python) | saas-retriever GitHub today; Slack / Jira / Confluence / Notion / GitLab / Bitbucket land as saas-retriever ships them |
| Output | json, sarif (2.1.0), table |
| Engine | concurrent scan, keyword pre-filter, finding dedup |
| Release | tag-pushed GoReleaser (`vX.Y.Z`) and PyPI trusted publishing (`py-vX.Y.Z`) |

## Development

```sh
go test ./... -race      # full test suite, race-clean
go build ./...
```

Releases are triggered exclusively by tag pushes that fan out to
GoReleaser / PyPI via GitHub Actions trusted publishing. `main` push
runs build and tests only — it does not publish. The agent harness
under `.claude/` drives meaningful changes; see `CLAUDE.md` for trigger
rules.

## License

AGPL-3.0 (matching pleno-anonymize).
