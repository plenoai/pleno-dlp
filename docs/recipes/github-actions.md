# GitHub Actions integration

Scan every push and PR with pleno-dlp, surface findings in GitHub
Code Scanning, and gate merges on Critical findings.

```yaml
# .github/workflows/secret-scan.yml
name: secret-scan
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  security-events: write   # required to upload SARIF to Code Scanning

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0   # so `scan git --since` sees history

      - name: Install pleno-dlp
        run: |
          curl -sSL https://github.com/plenoai/pleno-dlp/releases/latest/download/pleno-dlp_linux_amd64.tar.gz \
            | tar xz -C /usr/local/bin pleno-dlp

      - name: Scan filesystem
        run: |
          pleno-dlp scan filesystem . \
            --format sarif \
            --fail-on critical \
            --allowlist .pleno-allow.json \
            > findings.sarif
        continue-on-error: true   # SARIF upload still runs on findings

      - name: Upload SARIF to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: findings.sarif
```

## Scan only the diff on PRs (faster)

Use the merge-base diff instead of the full filesystem:

```yaml
- name: Scan diff
  if: github.event_name == 'pull_request'
  run: |
    git fetch origin ${{ github.base_ref }} --depth=1
    BASE=$(git merge-base HEAD origin/${{ github.base_ref }})
    git diff "$BASE"...HEAD | pleno-dlp scan stdin \
      --label "diff:${{ github.head_ref }}" \
      --format sarif > findings.sarif
```

## Gate merges with --fail-on

| `--fail-on`  | Exit 1 when … |
|--------------|---------------|
| `any`        | any finding emitted (default) |
| `info`       | severity ≥ Info |
| `low`        | severity ≥ Low |
| `medium`     | severity ≥ Medium (PII trips) |
| `high`       | severity ≥ High (unverified secrets trip) |
| `critical`   | severity ≥ Critical (verified secrets only) |

Pair with `--verify` for the strictest mode: only confirmed-active
secrets fail the build.

```yaml
- run: pleno-dlp scan filesystem . --verify --fail-on critical
```

## Verify rate limiting

`--verify` against many candidate keys can trigger upstream rate limits.

```sh
pleno-dlp scan filesystem . --verify --verify-rps 30
pleno-dlp scan filesystem . --verify --verify-rps 0    # no limiter
```
