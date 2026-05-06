# pleno-secret-scanner

Go-native secret scanner with trufflehog-compatible detector interfaces and a fresh source-connector layer.

Scope:
- **Detectors** — port of trufflehog's `Detector` interface (`Keywords`, `FromData`, `Type`, `Verify`). Roadmap covers cloud (AWS/GCP/Azure), VCS (GitHub/GitLab), SaaS (Slack/Stripe/Notion), and AI providers (OpenAI/Anthropic). MVP ships AWS, GitHub PAT, Slack bot, OpenAI, and Anthropic.
- **Sources** — reimplemented connector layer (`pkg/sources/`) covering filesystem, git, GitHub, GitLab, S3, GCS, Slack, Jira, Confluence, and more. Same `Source` chunk-emission contract as trufflehog so detectors are reusable. MVP ships filesystem.
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
