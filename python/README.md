# pleno-dlp (Python)

Unified DLP scanner for SaaS content — **secrets** (trufflehog /
gitleaks / native regex) and **PII** (delegating to
[pleno-anonymize](https://github.com/plenoai/pleno-anonymize)) — backed
by [saas-retriever](https://github.com/plenoai/saas-retriever) for
API-only source collection.

The Go binary in this repo (`cmd/pleno-dlp`) remains for filesystem-only
scans; the Python package is the path forward for SaaS.

## Install

```sh
uv tool install pleno-dlp
# or
pipx install pleno-dlp

# Add the PII backend (pulls pleno-anonymize):
uv tool install 'pleno-dlp[pii]'
```

## Usage

```sh
# Secret scan over an entire GitHub org (code + issues + PRs across every repo)
GITHUB_TOKEN=ghp_... pleno-dlp scan github --owner plenoai

# Scan a single repo, only code, with trufflehog verification
pleno-dlp scan github --owner plenoai --repo saas-retriever \
    --resource code --backend trufflehog

# Issue + PR conversations only, PII detection (requires pleno-anonymize)
pleno-dlp scan github --owner plenoai \
    --resource issues --resource prs --backend pii

# SARIF output for GitHub code-scanning ingestion
pleno-dlp scan github --owner plenoai \
    --format sarif > findings.sarif
```

Auth resolution: `--token` → `GITHUB_TOKEN` env var → `gh auth token`.
Anonymous works for public content but is rate-limited to 60 req/h.

## Backends

| Backend | Class | Verifies | System dep |
|---|---|---|---|
| trufflehog | secret | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | secret | no | `gitleaks` CLI on PATH |
| native | secret | no | none — bundled regex (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |
| pii | PII | n/a | `pleno-anonymize` (installed via `pleno-dlp[pii]` extra) |

## Connectors

Anything `saas-retriever` provides. Today: **github** with org-wide
enumeration plus per-repo code / issues / PRs (comments and unified
diffs). Slack / Jira / Confluence / Notion / GitLab / Bitbucket land as
standalone API connectors in subsequent saas-retriever releases.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
