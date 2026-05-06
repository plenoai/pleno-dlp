# pleno-secret-scanner (Python)

Python CLI that scans SaaS content for leaked secrets, backed by
[saas-scraper](https://github.com/plenoai/saas-scraper) for source
collection and a pluggable detection backend (trufflehog, gitleaks,
or a tiny built-in regex set).

The Go binary in this repo (`cmd/pleno-secret-scanner`) remains for
filesystem-only scans; the Python package is the path forward for any
SaaS source.

## Install

```sh
uv tool install pleno-secret-scanner
# or
pipx install pleno-secret-scanner
playwright install chromium
```

## Usage

```sh
# Scan a Slack workspace using the trufflehog backend (requires trufflehog on PATH)
pleno-secret-scanner scan slack --workspace acme --backend trufflehog

# Scan a GitHub repo with the built-in native backend (no system deps)
pleno-secret-scanner scan github --owner plenoai --repo saas-scraper

# Output formats
pleno-secret-scanner scan slack --workspace acme --format sarif > findings.sarif
```

## Backends

| Backend | Verifies | System dep |
|---|---|---|
| trufflehog | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | no | `gitleaks` CLI on PATH |
| native | no | none — bundled regex set (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |

## Connectors

Anything `saas-scraper` provides: filesystem, slack, github, gitlab,
bitbucket, jira, confluence, notion. New connectors land in saas-scraper
and become immediately available here.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
