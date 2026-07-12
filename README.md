<p align="center">
  <img src="docs/assets/banner.png" alt="Pleno DLP banner">
</p>

<h1 align="center">Pleno DLP</h1>

<p align="center">
  DLP scanner for secrets and PII. Single Go binary.
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
    <img alt="go version" src="https://img.shields.io/badge/go-1.25.8-00ADD8?logo=go&logoColor=white">
  </a>
</p>

```sh
brew install plenoai/tap/pleno-dlp   # signed release binary
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

pleno-dlp protect
pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
pleno-dlp scan filesystem ./repo --format sarif > findings.sarif
```

## Sources

`filesystem`, `git` history (branch, depth, and time filters), `stdin`,
and SaaS connectors: GitHub, GitLab, Bitbucket, Slack, Notion, Confluence,
Jira, and more.

```sh
pleno-dlp scan git --repo ./repo --branch main --max-depth 500
git diff | pleno-dlp scan stdin --label git-diff
pleno-dlp scan github --org acme
pleno-dlp sources list
```

## Detectors

619 built-in detector types ([counting method](docs/counts.md)),
[benchmarked against trufflehog and gitleaks](docs/comparison.md) for
recall, noise, and verification value. Table, JSON, or SARIF output;
allowlists and org-specific rules via config.

```sh
pleno-dlp detectors list
pleno-dlp scan filesystem ./repo --format sarif > findings.sarif
```

## Verification

Findings are checked against the provider API by default where one
exists. Verdicts are three-valued: verified (confirmed live at scan
time), unverified, indeterminate. Detectors that cannot verify are
classified in [`docs/verify-coverage.md`](docs/verify-coverage.md).

```sh
pleno-dlp detectors list --verify-status
```

## Revocation

`pleno-dlp revoke` invalidates leaked GitHub, GitLab, Slack, and Stripe
restricted-key credentials from the CLI; AWS additionally needs
operator-supplied IAM admin context. Each attempt writes a
schema-versioned [JSON Lines audit record](docs/audit-trail-schema.md)
(`--audit-trail <path>`, default stderr). Gating rules:
[`docs/revoke-support.md`](docs/revoke-support.md)

```sh
echo "$LEAKED_TOKEN" | PLENO_DLP_ALLOW_REVOKE=1 pleno-dlp revoke --detector github --secret - --confirm
pleno-dlp revoke --detector slack --secret xoxb-... --dry-run
pleno-dlp detectors list --revoke-support
```

## PII detection

Opt-in. Engines and setup in [`docs/pii-detection.md`](docs/pii-detection.md).

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
```

## GitHub Action

```yaml
- uses: actions/checkout@v7
- uses: plenoai/pleno-dlp@v0.62.0
  with:
    sarif-file: results.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: results.sarif
```

The action [cosign-verifies the pinned release binary](docs/output-and-gating.md#github-action)
before running it.

## Agent hooks

`pleno-dlp hooks install claude-code|cursor` runs an offline
`scan stdin --no-verify` inside the agent's own hook, flagging a
credential before it is written or committed. Latency numbers are in
[`docs/hooks.md`](docs/hooks.md).

```sh
pleno-dlp hooks install claude-code
pleno-dlp hooks install cursor
```

## License

[AGPL-3.0](LICENSE)
