# Output and gating

`pleno-dlp` can emit human-readable tables, JSON, or SARIF, and can fail
the process when findings reach a chosen severity threshold.

## Output formats

```sh
pleno-dlp scan filesystem ./repo --format table
pleno-dlp scan filesystem ./repo --format json
pleno-dlp scan filesystem ./repo --format sarif
```

SARIF output is GitHub Code Scanning compatible:

```yaml
- run: pleno-dlp scan filesystem . --format sarif > findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

## Severity defaults

| Finding | Severity |
|---|---|
| Verified secret | Critical |
| Unverified named secret detector | High |
| Generic high entropy / JWT / PEM unverified | Medium |
| PII | Medium |

## Exit-code gating

`--fail-on` controls the exit code:

```sh
pleno-dlp scan filesystem ./repo --fail-on critical
pleno-dlp scan filesystem ./repo --fail-on high
pleno-dlp scan filesystem ./repo --fail-on any
```

## Detector scoping

Detector scoping is case-insensitive and fails closed on unknown names:

```sh
pleno-dlp scan filesystem ./repo --exclude-detectors GenericHighEntropy
pleno-dlp scan filesystem ./repo --include-detectors AWS,GitHub,Stripe
```

## Related docs

- [`docs/recipes/README.md`](recipes/README.md)
- [`docs/recipes/github-actions.md`](recipes/github-actions.md)
- [`docs/recipes/gitlab-ci.md`](recipes/gitlab-ci.md)
- [`docs/recipes/pre-commit.md`](recipes/pre-commit.md)
