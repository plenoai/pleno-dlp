# pleno-dlp (Python)

Unified DLP scanner for SaaS content — **secrets** (trufflehog /
gitleaks / native regex) and **PII** (delegating to
[pleno-anonymize](https://github.com/plenoai/pleno-anonymize)). One
plugin model: every source (github, slack, jira, …) and every detector
(native, trufflehog, gitleaks, pii) is a *connector* registered under
`pleno_dlp.connectors.*`, distinguished by `ConnectorSpec.role`
(`source` or `detector`). `pip install pleno-dlp` pulls one wheel
exposing one console script (`pleno-dlp`).

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

The CLI is connector-agnostic: knobs flow through the generic
``--option key=value`` flag (sources) and ``--detector-option`` /
``-D key=value`` (detectors). Run
``pleno-dlp describe <connector>`` for the accepted keys, types,
defaults, and which ones are secrets.

```sh
# Discover what's registered
pleno-dlp list                       # everything
pleno-dlp list --role source         # SaaS sources only
pleno-dlp list --role detector       # detection backends only
pleno-dlp describe github
pleno-dlp describe trufflehog

# Secret scan over an entire GitHub org with the default native detector
GITHUB_TOKEN=ghp_... pleno-dlp scan github --option owner=plenoai

# Scan a single repo, only code, with trufflehog verification
pleno-dlp scan github \
    --option owner=plenoai --option repo=pleno-dlp \
    --option resources=code --detector trufflehog

# Issue + PR conversations only, PII detection (requires pleno-anonymize)
pleno-dlp scan github --option owner=plenoai \
    --option resources=issues,prs --detector pii \
    --pii-base-url http://localhost:8000

# SARIF output for GitHub code-scanning ingestion
pleno-dlp scan github --option owner=plenoai \
    --format sarif > findings.sarif

# Slack workspace — same shape, different source connector
pleno-dlp scan slack --token xoxb-... --option include_threads=false
```

Auth resolution for github: `--token` → `GITHUB_TOKEN` env var →
`gh auth token`. Anonymous works for public content but is rate-limited
to 60 req/h. Other source connectors take their token via `--token`
(shorthand for `--option token=…`) or via `--option api_token=…` /
`--option access_token=…` depending on the auth mode (see
`describe`).

## Detectors

| Detector | Class | Verifies | System dep |
|---|---|---|---|
| trufflehog | secret | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | secret | no | `gitleaks` CLI on PATH |
| native | secret | no | none — bundled regex (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |
| pii | PII | n/a | `pleno-anonymize` HTTP API (installed via `pleno-dlp[pii]` extra) |

## Source connectors

Each source self-describes via a `ConnectorSpec` (auth modes,
resources, options, runtime capabilities). Today: **github**, **gitlab**,
**bitbucket** (cloud + server), **slack** (xoxb / xoxp), **notion**,
**confluence** (cloud + datacenter), **jira** (cloud + datacenter).
Run `pleno-dlp list --role source` for the live list and
`pleno-dlp describe <name>` for the option sheet.

### Adding a new connector (source or detector)

1. Create `python/src/pleno_dlp/connectors/<name>.py`.
2. Implement the right Protocol:
   - **Source**: `discover`, `fetch`, `discover_and_fetch`,
     `capabilities`, `close`. Keep one `httpx.AsyncClient` per instance.
   - **Detector**: a single `async def scan(self, doc: Document) ->
     AsyncIterator[Finding]`.
3. Declare a `spec: ClassVar[ConnectorSpec] = ConnectorSpec(...)`
   with the right `role` (`ConnectorRole.SOURCE` or
   `ConnectorRole.DETECTOR`), `name`, `kind`, `summary`, `auth_modes`,
   `resources` (sources only), `options` (every `__init__` kwarg you
   want operators to set), and `capabilities` (sources only).
4. End the module with `registry.register("<name>", <Class>)`.
5. Wire the import in `pleno_dlp/connectors/__init__.py`.
6. Add fixtures + tests under `python/tests/connectors/test_<name>.py`
   using `httpx.MockTransport` (or stdlib mocks for offline detectors).

Once the spec lands, `pleno-dlp scan <source> --detector <det>`,
`pleno-dlp list`, and `pleno-dlp describe` all work without touching
the CLI.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
