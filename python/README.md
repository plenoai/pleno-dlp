# pleno-dlp (Python)

Unified DLP scanner for SaaS content — **secrets** (trufflehog /
gitleaks / native regex) and **PII** (delegating to
[pleno-anonymize](https://github.com/plenoai/pleno-anonymize)). The
SaaS source layer is bundled directly under
`pleno_dlp.connectors.*` (from 0.9.0); `pip install pleno-dlp` pulls
one wheel exposing one console script (`pleno-dlp`).

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

The CLI is connector-agnostic: connector knobs flow through the generic
``--option key=value`` flag. Run ``pleno-dlp describe <connector>`` to
see the accepted keys, types, defaults, and which ones are secrets.

```sh
# Discover what each connector takes
pleno-dlp list-connectors
pleno-dlp describe github

# Secret scan over an entire GitHub org (code + issues + PRs across every repo)
GITHUB_TOKEN=ghp_... pleno-dlp scan github --option owner=plenoai

# Scan a single repo, only code, with trufflehog verification
pleno-dlp scan github \
    --option owner=plenoai --option repo=pleno-dlp \
    --option resources=code --backend trufflehog

# Issue + PR conversations only, PII detection (requires pleno-anonymize)
pleno-dlp scan github --option owner=plenoai \
    --option resources=issues,prs --backend pii

# SARIF output for GitHub code-scanning ingestion
pleno-dlp scan github --option owner=plenoai \
    --format sarif > findings.sarif

# Slack workspace — the same shape, different connector
pleno-dlp scan slack --token xoxb-... --option include_threads=false
```

Auth resolution for github: `--token` → `GITHUB_TOKEN` env var →
`gh auth token`. Anonymous works for public content but is rate-limited
to 60 req/h. Other connectors take their token via `--token` (shorthand
for `--option token=…`) or via `--option api_token=…` /
`--option access_token=…` depending on the auth mode (see
`describe`).

## Backends

| Backend | Class | Verifies | System dep |
|---|---|---|---|
| trufflehog | secret | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | secret | no | `gitleaks` CLI on PATH |
| native | secret | no | none — bundled regex (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |
| pii | PII | n/a | `pleno-anonymize` (installed via `pleno-dlp[pii]` extra) |

## Connectors

Each connector self-describes via a `ConnectorSpec` (auth modes,
resources, options, runtime capabilities). Today: **github**, **gitlab**,
**bitbucket** (cloud + server), **slack** (xoxb / xoxp), **notion**,
**confluence** (cloud + datacenter), **jira** (cloud + datacenter).
Run `pleno-dlp list-connectors` for the live list and
`pleno-dlp describe <name>` for the option sheet.

### Adding a new SaaS connector

1. Create `python/src/pleno_dlp/connectors/<name>.py`.
2. Implement the `Connector` protocol (`discover`, `fetch`,
   `discover_and_fetch`, `capabilities`, `close`). Keep one
   `httpx.AsyncClient` per instance.
3. Declare a `spec: ClassVar[ConnectorSpec] = ConnectorSpec(...)` —
   `name`, `kind`, `summary`, `auth_modes`, `resources`, `options`
   (every `__init__` kwarg you want operators to set), and
   `capabilities`. The registry rejects registration without a
   matching spec.
4. End the module with `registry.register("<name>", <Class>)`.
5. Wire the import in `pleno_dlp/connectors/__init__.py` so
   `import pleno_dlp` populates the registry.
6. Add fixtures + tests under `python/tests/connectors/test_<name>.py`
   using `httpx.MockTransport`.

Once the spec lands, `pleno-dlp scan <name>` and
`pleno-dlp describe <name>` work without touching the CLI.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
