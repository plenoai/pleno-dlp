# pleno-secret-scanner (Python)

Python CLI that scans SaaS content for leaked secrets, backed by
[saas-retriever](https://github.com/plenoai/saas-retriever) for source
collection (API-only — no scraping) and a pluggable detection backend
(trufflehog, gitleaks, or a tiny built-in regex set).

The Go binary in this repo (`cmd/pleno-secret-scanner`) remains for
filesystem-only scans; the Python package is the path forward for SaaS.

## Install

```sh
uv tool install pleno-secret-scanner
# or
pipx install pleno-secret-scanner
```

## Usage

```sh
# Scan an entire GitHub org (code + issues + PRs across every repo)
GITHUB_TOKEN=ghp_... pleno-secret-scanner scan github --owner plenoai

# Scan a single repo, only code, with trufflehog verification
pleno-secret-scanner scan github --owner plenoai --repo saas-retriever \
    --resource code --backend trufflehog

# Issue + PR conversations only (skip code)
pleno-secret-scanner scan github --owner plenoai \
    --resource issues --resource prs

# SARIF output for GitHub code-scanning ingestion
pleno-secret-scanner scan github --owner plenoai \
    --format sarif > findings.sarif
```

Auth resolution: `--token` → `GITHUB_TOKEN` env var → `gh auth token`.
Anonymous works for public content but is rate-limited to 60 req/h.

## Backends

| Backend | Verifies | System dep |
|---|---|---|
| trufflehog | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | no | `gitleaks` CLI on PATH |
| native | no | none — bundled regex set (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |

## Connectors

Anything `saas-retriever` provides. v0.1.x ships **github** with
org-wide enumeration + per-repo code / issues / PRs (with comments and
unified diffs). Slack / Jira / Confluence / Notion / GitLab / Bitbucket
return as standalone API connectors in subsequent saas-retriever
releases.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
