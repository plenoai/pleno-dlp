# pleno-dlp

Unified DLP scanner for secrets and PII. One Go binary scans the
filesystem, local git history, stdin, and SaaS sources.

```sh
go install github.com/plenoai/pleno-dlp/cmd/pleno-dlp@latest

pleno-dlp protect
pleno-dlp scan filesystem ./repo
pleno-dlp scan git --repo ./repo --max-depth 200
pleno-dlp scan filesystem ./repo --format sarif --verify > findings.sarif
```

## Coverage

- 600 built-in detector types.
- Secret detectors that can safely call an upstream provider implement
  `Verify`; enable that path with `--verify`.
- Deliberately unverified detectors are documented in
  [`docs/verify-coverage.md`](docs/verify-coverage.md).
- PII detection is opt-in through `--pii-engine=anonymize` or
  `--pii-engine=openai-pf`; PII findings set
  `properties.finding_class=pii`.

Useful introspection:

```sh
pleno-dlp detectors list
pleno-dlp detectors list --format json
pleno-dlp detectors list --verify-status
pleno-dlp detectors list --revoke-support
```

## Scan sources

```sh
# Filesystem
pleno-dlp scan filesystem ./repo \
  --include 'src/**' \
  --exclude '**/*_test.go'

# Local git history
pleno-dlp scan git --repo ./repo --branch main --max-depth 500
pleno-dlp scan git --repo ./repo --since 2024-01-01T00:00:00Z

# Stdin
git diff | pleno-dlp scan stdin --label git-diff
kubectl get secret app-config -o yaml | pleno-dlp scan stdin
```

Filesystem scans exclude common dependency/build directories by default:
`.git`, `.hg`, `.svn`, `node_modules`, `vendor`, `target`, `dist`,
`build`, `__pycache__`, `.venv`, and `.tox`. Use
`--no-default-excludes` when you intentionally want those paths.

Native SaaS connectors inherit the same persistent scan flags
(`--format`, `--verify`, `--include-detectors`, `--exclude-detectors`,
and others):

| Connector | Scope | Auth |
|---|---|---|
| `github` | `--org` or `--repo`; optional `--include-comments` | `--token` or `GITHUB_TOKEN`; `--api-base` supports GHE |
| `gitlab` | `--group` or `--project`; optional `--include-comments` | `--token` or `GITLAB_TOKEN`; `--api-base` supports self-hosted |
| forge API comments | issue / PR / MR / ticket comments | see [`docs/source-forge-api-comments.md`](docs/source-forge-api-comments.md) |
| `bitbucket` | `--workspace` or `--repo` | Bearer `--token`, or `--username` + `--app-password` |
| `slack` | optional `--channel` | `--token` or `SLACK_TOKEN` |
| `notion` | optional `--query` | `--token` or `NOTION_TOKEN` |
| `confluence` | optional `--space` | Cloud: `--site --email --token`; Data Center: `--api-base --token` |
| `jira` | optional `--project` or `--jql` | Cloud: `--site --email --token`; Data Center: `--api-base --token` |

```sh
pleno-dlp scan github --org acme
pleno-dlp scan github --repo acme/widget --include-comments
pleno-dlp scan gitlab --project acme/widget --include-comments
pleno-dlp scan slack --channel C0123456789
pleno-dlp scan jira --site acme --email alice@acme.com --project PROJ
```

Forge issue/PR comment scans read API-only review text that normal Git
history scans cannot see. They do not clone repository contents; use
`scan git` or `scan filesystem` for source blobs.

Validate connector credentials without scanning:

```sh
pleno-dlp verify github --token "$GITHUB_TOKEN"
pleno-dlp verify gitlab --token "$GITLAB_TOKEN"
pleno-dlp verify slack  --token "$SLACK_TOKEN"
pleno-dlp verify notion --token "$NOTION_TOKEN"
```

## PII detection

PII scanning is off by default.

| Engine | Flag | Detector | Notes |
|---|---|---|---|
| pleno-anonymize | `--pii-engine=anonymize` | `PIIAnonymize` | ja-first NER + regex; fast cold start |
| openai/privacy-filter | `--pii-engine=openai-pf` | `PIIOpenAIPF` | 1.5B-param classifier; GPU recommended |

```sh
pleno-dlp scan filesystem ./src --pii-engine=anonymize
pleno-dlp scan filesystem ./src --pii-engine=openai-pf
```

Both engines run as loopback HTTP subprocesses and are torn down at the
end of the scan. Runtime requirements: `uv`, Python 3.12+, and `git`
for default `git+` sources. Docker is not required.

Effective defaults:

| Flag | Default | Meaning |
|---|---|---|
| `--pii-engine` | `off` | `off`, `anonymize`, or `openai-pf` |
| `--pii-engine-cmd` | engine-specific | `pleno-dlp pii-server --port {PORT}` or `pleno-dlp openai-pf-server --port {PORT}` |
| `--pii-engine-port` | `0` | auto-allocate a loopback port |
| `--pii-engine-language` | `auto` | `anonymize` only: `ja`, `en`, or `auto` |
| `--pii-engine-device` | `auto` | `openai-pf` only: `auto`, `cpu`, `cuda`, or `mps` |
| `--pii-engine-ready-timeout` | `0` | engine default: 60s for `anonymize`, 300s for `openai-pf` |
| `--pii-engine-request-timeout` | `10s` | per `/api/analyze` request |

Direct server commands are available for local debugging:

```sh
pleno-dlp pii-server --port 8080
pleno-dlp pii-server --git-ref v0.5.0
pleno-dlp openai-pf-server --port 8081
pleno-dlp openai-pf-server --device cuda
```

Both server commands refuse public bind addresses; use loopback,
RFC1918, or link-local hosts only.

## Output and gating

```sh
pleno-dlp scan filesystem ./repo --format table
pleno-dlp scan filesystem ./repo --format json
pleno-dlp scan filesystem ./repo --format sarif
```

Severity defaults:

| Finding | Severity |
|---|---|
| Verified secret | Critical |
| Unverified named secret detector | High |
| Generic high entropy / JWT / PEM unverified | Medium |
| PII | Medium |

`--fail-on` controls the exit code:

```sh
pleno-dlp scan filesystem ./repo --fail-on critical
pleno-dlp scan filesystem ./repo --fail-on high
pleno-dlp scan filesystem ./repo --fail-on any
```

Detector scoping is case-insensitive and fails closed on unknown names:

```sh
pleno-dlp scan filesystem ./repo --exclude-detectors GenericHighEntropy
pleno-dlp scan filesystem ./repo --include-detectors AWS,GitHub,Stripe
```

SARIF output is GitHub Code Scanning compatible:

```yaml
- run: pleno-dlp scan filesystem . --format sarif > findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

See [`docs/recipes/`](docs/recipes/) for CI and pre-commit workflows.

## Allowlist and custom rules

Allow known false positives with `.pleno-allow.json` or `--allowlist`:

```json
{
  "entries": [
    {"detector": "AWS", "raw": "AKIAIOSFODNN7EXAMPLE", "reason": "documented fixture"},
    {"path": "fixtures/**/*.env", "reason": "local test fixtures"},
    {"raw_regex": "^sk-test_", "reason": "Stripe test-mode keys"}
  ]
}
```

Add organization-specific detectors with `--rules`:

```json
[
  {
    "name": "ACME Internal API Key",
    "keywords": ["ACME_API_KEY", "x-acme-token"],
    "regex": "ACME_[A-Z0-9]{20}",
    "entropy_min": 3.5,
    "severity": "high",
    "verify_url": "https://api.acme.example/verify",
    "verify_header": "Authorization: Bearer {{ .Secret }}"
  }
]
```

```sh
pleno-dlp scan filesystem ./repo --rules ./acme-rules.json
```

## Revocation

`pleno-dlp revoke` invalidates supported leaked credentials through the
provider API. Supported detector families: GitHub, GitLab, Slack, AWS,
and Stripe restricted keys.

```sh
echo "$LEAKED_TOKEN" | pleno-dlp revoke --detector github --secret - --confirm
pleno-dlp revoke --detector slack --secret xoxb-... --dry-run
```

Revocation is irreversible. The CLI requires `--confirm` or
`--dry-run`; non-interactive confirmed runs also require
`PLENO_DLP_ALLOW_REVOKE=1`.

During scans, `--revoke-on-verified` revokes only verified findings and
therefore requires both `--verify` and `PLENO_DLP_ALLOW_REVOKE=1`.
Preview with `--revoke-dry-run`.

Details: [`docs/revoke-support.md`](docs/revoke-support.md).

## Development

```sh
go test ./... -race
go build ./...
```

Releases are tag-driven:

- `vX.Y.Z` tag push runs GoReleaser trusted publishing.
- `main` push runs build and tests only.

Historical throughput data lives in
[`docs/benchmarks.md`](docs/benchmarks.md).

## License

[AGPL-3.0](LICENSE).
