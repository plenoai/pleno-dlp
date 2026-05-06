# pleno-secret-scanner

Two surfaces in one repo:

- **Python package** (`python/`) — the path forward for SaaS sources. Consumes
  [saas-scraper](https://pypi.org/project/saas-scraper/) for content
  collection (Slack, GitHub, GitLab, Bitbucket, Jira, Confluence, Notion via
  Chrome) and pluggable detection backends (trufflehog, gitleaks, native
  regex). Tag pattern: `py-vX.Y.Z`. See [`python/README.md`](python/README.md).
- **Go binary** (this directory) — the original filesystem scanner with
  trufflehog-compatible detector interfaces. Tag pattern: `vX.Y.Z`.

## Go binary scope

- **Detectors** — port of trufflehog's `Detector` interface (`Keywords`, `FromData`, `Type`, `Verify`). Roadmap covers cloud (AWS/GCP/Azure), VCS (GitHub/GitLab), SaaS (Slack/Stripe/Notion), and AI providers (OpenAI/Anthropic). MVP ships AWS, GitHub PAT, Slack bot, OpenAI, and Anthropic.
- **Sources** — reimplemented connector layer (`pkg/sources/`) covering filesystem only on the Go side. SaaS sources have moved to the Python package via `saas-scraper`.
- **Engine** — concurrent scan loop, dedup, false-positive filter, output (JSON / SARIF / table).
- **CLI** — cobra-based: `pleno-secret-scanner scan <path> [--format json|sarif|table] [--verify] [--concurrency N]`.

## Install

```sh
go install github.com/plenoai/pleno-secret-scanner/cmd/pleno-secret-scanner@latest
```

Or grab a pre-built archive from [releases](https://github.com/plenoai/pleno-secret-scanner/releases) (linux / darwin / windows × amd64 / arm64).

## Usage

```sh
pleno-secret-scanner scan ./path/to/repo
pleno-secret-scanner scan ./path --format sarif > findings.sarif
pleno-secret-scanner scan ./path --verify           # confirms candidates against upstream APIs
```

Exit code is `1` when at least one finding is emitted, `0` otherwise.

## Status

| Area | State |
|---|---|
| Detectors | AWS, GitHub PAT, Slack bot token, OpenAI, Anthropic — each with `Verify()` |
| Sources | filesystem (recursive walk, skips binary / oversize / symlinks) |
| Output | json, sarif (2.1.0), table |
| Engine | concurrent scan, keyword pre-filter, finding dedup |
| Release | `v0.1.0` published via tag-pushed GoReleaser trusted publishing |

Roadmap: additional sources (`git`, `github`, `s3`, `gcs`, `slack`, `jira`, `confluence`), additional detectors (GCP, Azure, GitLab, Stripe, Notion, JWT, generic high-entropy), and a `detect` subcommand that streams stdin.

## Development

```sh
go test ./... -race      # full test suite, race-clean
go build ./...
```

Releases are triggered exclusively by `vX.Y.Z` tag pushes that fan out to GoReleaser via GitHub Actions trusted publishing. `main` push runs build and tests only — it does not publish. The agent harness under `.claude/` drives meaningful changes; see `CLAUDE.md` for trigger rules.

## License

AGPL-3.0 (matching pleno-anonymize).
