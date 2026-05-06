# pleno-secret-scanner

Go-native secret scanner with trufflehog-compatible detector interfaces and a fresh source-connector layer.

Scope:
- **Detectors** — port of trufflehog's `Detector` interface (`Keywords`, `FromData`, `Type`, `Verify`). Initial set covers cloud (AWS/GCP/Azure), VCS (GitHub/GitLab), SaaS (Slack/Stripe/Notion), and AI providers (OpenAI/Anthropic).
- **Sources** — reimplemented connector layer (`pkg/sources/`) covering filesystem, git, GitHub, GitLab, S3, GCS, Slack, Jira, Confluence, and more. Same `Source` chunk-emission contract as trufflehog so detectors are reusable.
- **Engine** — concurrent scan loop, dedup, false-positive filter, output (JSON / SARIF / table).
- **CLI** — cobra-based: `pleno-secret-scanner <source-type> [args]`.

Distribution: tag push triggers GoReleaser via GitHub Actions (trusted publishing). `go install github.com/plenoai/pleno-secret-scanner/cmd/pleno-secret-scanner@latest` after the first release.

## Status

Bootstrapped harness only. Implementation work is driven by the agent team defined under `.claude/`. See `CLAUDE.md` for trigger rules.

## License

AGPL-3.0 (matching pleno-anonymize).
