# pleno-dlp (Python)

Unified DLP scanner for SaaS content — **secrets** (trufflehog /
gitleaks / native regex) and **PII** (delegating to
[pleno-anonymize](https://github.com/plenoai/pleno-anonymize)).

A *connector* models a SaaS provider — github, gitlab, bitbucket,
slack, notion, confluence, jira — and walks its content through the
provider's API. A *detection engine* turns text into findings; the
four built-ins (`native`, `trufflehog`, `gitleaks`, `pii`) live under
`pleno_dlp.engines` and apply equally to any connector's output.
Every connector self-describes via `ConnectorSpec.capabilities`
(`SOURCE`, optional `VERIFY` / `REVOKE` for secret-lifecycle ops).

`pip install pleno-dlp` pulls one wheel exposing one console script
(`pleno-dlp`). The Go binary in this repo (`cmd/pleno-dlp`) remains
for filesystem-only scans; the Python package is the path forward
for SaaS.

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
``--option key=value`` flag, and the detection engine is picked with
``--engine``. Run ``pleno-dlp describe <connector>`` for the accepted
keys, types, defaults, and which ones are secrets.

```sh
# Discover what's registered
pleno-dlp list                              # connectors + engines
pleno-dlp list --capability verify          # connectors with VERIFY
pleno-dlp describe github

# Secret scan over an entire GitHub org with the default native engine
GITHUB_TOKEN=ghp_... pleno-dlp scan github --option owner=plenoai

# Scan a single repo, only code, with trufflehog verification
pleno-dlp scan github \
    --option owner=plenoai --option repo=pleno-dlp \
    --option resources=code --engine trufflehog

# Issue + PR conversations only, PII detection (requires pleno-anonymize)
pleno-dlp scan github --option owner=plenoai \
    --option resources=issues,prs --engine pii \
    --pii-base-url http://localhost:8000

# SARIF output for GitHub code-scanning ingestion
pleno-dlp scan github --option owner=plenoai \
    --format sarif > findings.sarif

# Slack workspace — same shape, different source connector
pleno-dlp scan slack --token xoxb-... --option include_threads=false

# Confirm a leaked github PAT is still live
pleno-dlp verify github --token ghp_…
```

Auth resolution for github: `--token` → `GITHUB_TOKEN` env var →
`gh auth token`. Anonymous works for public content but is rate-limited
to 60 req/h. Other source connectors take their token via `--token`
(shorthand for `--option token=…`) or via `--option api_token=…` /
`--option access_token=…` depending on the auth mode (see
`describe`).

## Detection engines

Engines are not connectors — they are stateless utilities that turn a
``Document.text`` into ``Finding``\\s. Pick one with ``--engine``.

| Engine | Class | Verifies | System dep |
|---|---|---|---|
| trufflehog | secret | yes (per-detector) | `trufflehog` CLI on PATH |
| gitleaks | secret | no | `gitleaks` CLI on PATH |
| native | secret | no | none — bundled regex (AWS, GitHub PAT, Slack bot, OpenAI, Anthropic) |
| pii | PII | n/a | `pleno-anonymize` HTTP API (installed via `pleno-dlp[pii]` extra) |

## Source connectors

Each connector self-describes via a `ConnectorSpec` (auth modes,
resources, options, runtime capabilities). Today: **github**, **gitlab**,
**bitbucket** (cloud + server), **slack** (xoxb / xoxp), **notion**,
**confluence** (cloud + datacenter), **jira** (cloud + datacenter).
Run `pleno-dlp list` for the live list and `pleno-dlp describe <name>`
for the option sheet.

### Capabilities

A connector advertises one or more capabilities:

* `Capability.SOURCE` — implements the `Connector` Protocol
  (`discover` / `fetch` / `capabilities`). Every shipped connector has
  this.
* `Capability.VERIFY` — implements the `Verifier` Protocol
  (`verify(secret) -> VerifyResult`). Today: **github** (probes
  `GET /user`).
* `Capability.REVOKE` — implements the `Revoker` Protocol
  (`revoke(secret) -> RevokeResult`). Reserved; no built-in connector
  has this yet — providers without a programmatic revoke endpoint
  should leave it unset and document the manual rotation flow.

`pleno-dlp verify <connector> --token …` exercises `VERIFY`. Exit
codes: `0` = LIVE, `1` = REVOKED, `2` = UNKNOWN/unsupported.

### Adding a new connector

1. Create `python/src/pleno_dlp/connectors/<name>.py`.
2. Implement at least the `Connector` Protocol (`discover`, `fetch`,
   `discover_and_fetch`, `capabilities`, `close`). Keep one
   `httpx.AsyncClient` per instance. Optionally add `verify(secret)` /
   `revoke(secret)` for lifecycle support.
3. Declare a `spec: ClassVar[ConnectorSpec] = ConnectorSpec(...)`
   with `name`, `kind`, `summary`, `capabilities` (frozenset of the
   `Capability` values you implement; defaults to `{SOURCE}`),
   `auth_modes`, `resources`, `options` (every `__init__` kwarg you
   want operators to set), and `runtime` (a `Capabilities` describing
   incremental / streaming / concurrency).
4. End the module with `registry.register("<name>", <Class>)`.
5. Wire the import in `pleno_dlp/connectors/__init__.py`.
6. Add fixtures + tests under `python/tests/connectors/test_<name>.py`
   using `httpx.MockTransport`.

Once the spec lands, `pleno-dlp scan <name> --engine <engine>`,
`pleno-dlp verify <name>`, `pleno-dlp list`, and
`pleno-dlp describe` all work without touching the CLI.

## Release

Tag `py-vX.Y.Z` triggers PyPI trusted publishing via GitHub Actions.
