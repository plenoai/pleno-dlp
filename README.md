<p align="center">
  <img src="docs/assets/banner.png" alt="Pleno DLP banner">
</p>

<h1 align="center">Pleno DLP</h1>

<p align="center">
  Unified DLP scanner for secrets and PII across filesystem, git, stdin, and SaaS sources.
</p>

<p align="center">
  <a href="https://github.com/plenoai/pleno-dlp/actions/workflows/test.yml">
    <img alt="test" src="https://github.com/plenoai/pleno-dlp/actions/workflows/test.yml/badge.svg?branch=main">
  </a>
  <a href="https://github.com/plenoai/pleno-dlp/releases">
    <img alt="release" src="https://img.shields.io/github/v/release/plenoai/pleno-dlp">
  </a>
  <a href="https://github.com/plenoai/pleno-dlp/blob/main/LICENSE">
    <img alt="license" src="https://img.shields.io/github/license/plenoai/pleno-dlp">
  </a>
  <a href="https://github.com/plenoai/pleno-dlp/blob/main/go.mod">
    <img alt="go version" src="https://img.shields.io/badge/go-1.25.0-00ADD8?logo=go&logoColor=white">
  </a>
</p>

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest
# or, on macOS/Linux with Homebrew:
brew install plenoai/tap/pleno-dlp

pleno-dlp protect
pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
pleno-dlp scan filesystem ./repo --format sarif > findings.sarif
```

The Homebrew formula (`plenoai/tap/pleno-dlp`) is published to the
[`plenoai/homebrew-tap`](https://github.com/plenoai/homebrew-tap) repository
by GoReleaser on every `vX.Y.Z` tag push; it always tracks the latest
signed release and pins a specific binary rather than floating on `@latest`
the way `go install` does.

## Target source

- `filesystem`: working trees, build outputs, arbitrary directories
- `git`: local history with branch / depth / time filters
- `stdin`: diffs, exports, and pipe-based checks
- SaaS: GitHub, GitLab, Bitbucket, Slack, Notion, Confluence, Jira

```sh
pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --branch main --max-depth 500
git diff | pleno-dlp scan stdin --label git-diff
pleno-dlp scan github --org acme
pleno-dlp sources list
```

`sources list` enumerates every registered core source and SaaS connector
from `pkg/sources/catalog.All()`, with a `CLI-WIRED` column marking whether
a `scan` subcommand exists yet — see
[`docs/comparison.md`](docs/comparison.md) §9 for the full
implemented/planned breakdown.

More connector detail: [`docs/source-forge-api-comments.md`](docs/source-forge-api-comments.md)

## Detect coverage

- 619 built-in detector types (registered in `pkg/detectors`; see
  [`docs/counts.md`](docs/counts.md) for what "detector type" counts)
- table / JSON / SARIF output
- custom allowlists and org-specific rules supported

```sh
pleno-dlp detectors list
pleno-dlp detectors list --format json
pleno-dlp scan filesystem ./repo --format sarif > findings.sarif
```

More output and CI detail: [`docs/output-and-gating.md`](docs/output-and-gating.md)

## GitHub Action

```yaml
- uses: actions/checkout@v7
- uses: plenoai/pleno-dlp@v0.59.0
  with:
    sarif-file: results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

The action downloads the pinned release binary for the runner's OS/arch
and cosign-verifies it (Sigstore keyless) before running anything. Details:
[`docs/output-and-gating.md`](docs/output-and-gating.md#github-action).

Measured comparison against trufflehog and gitleaks (synthetic and
real-world recall, noise, verification value, capability probes):
[`docs/comparison.md`](docs/comparison.md)

## Verification support

Provider-side validation runs by default where available.

```sh
pleno-dlp scan filesystem ./repo
pleno-dlp detectors list --verify-status
```

Coverage and unverified classes: [`docs/verify-coverage.md`](docs/verify-coverage.md)

## Revocation support

`pleno-dlp revoke` can invalidate supported leaked credentials for GitHub,
GitLab, Slack, AWS, and Stripe restricted keys — headlessly, from the CLI,
with no provider web console step. Among the OSS scanners we benchmark in
[`docs/comparison.md`](docs/comparison.md) (trufflehog, gitleaks), that is
currently unique to pleno-dlp; it is not a claim about commercial tools.

```sh
echo "$LEAKED_TOKEN" | pleno-dlp revoke --detector github --secret - --confirm
pleno-dlp revoke --detector slack --secret xoxb-... --dry-run
pleno-dlp detectors list --revoke-support
```

Every revoke attempt emits a schema-versioned JSON Lines audit-trail
record (`--audit-trail <path>`, falls back to stderr): [`docs/audit-trail-schema.md`](docs/audit-trail-schema.md)

Details and safety constraints: [`docs/revoke-support.md`](docs/revoke-support.md)

## PII detection

PII scanning is opt-in.

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
```

Advanced flags and engine setup:

- `pleno-dlp scan --help`
- `pleno-dlp pii-server --help`
- [`docs/pii-detection.md`](docs/pii-detection.md)

## Agent hooks

`pleno-dlp hooks install claude-code|cursor` wires a fast, offline
`scan stdin --no-verify` into the agent's own hook mechanism so a
credential gets flagged before it's written (claude-code) or committed
(cursor) — without waiting on CI.

```sh
pleno-dlp hooks install claude-code
pleno-dlp hooks install cursor
```

Measured hook latency and what each target installs:
[`docs/hooks.md`](docs/hooks.md)

## License

[AGPL-3.0](LICENSE).
