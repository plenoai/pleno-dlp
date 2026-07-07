# Output and gating

`pleno-dlp` can emit human-readable tables, JSON, or SARIF, and can fail
the process when findings reach a chosen severity threshold.

## Output formats

```sh
pleno-dlp scan filesystem ./repo --format table
pleno-dlp scan filesystem ./repo --format json
pleno-dlp scan filesystem ./repo --format sarif
```

JSON output includes a stable `secret_hash` field computed as
SHA-256 over the matched raw secret bytes. Pair-style detectors that
carry a second secret half also emit `secret_hash_v2`. The raw secret
value is not printed.

SARIF output is GitHub Code Scanning compatible:

```yaml
- run: pleno-dlp scan filesystem . --format sarif > findings.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: findings.sarif
```

## Verification verdicts

Verification is three-valued, not a boolean: a detector's `Verify` call can
confirm the secret is live (`verified`), confirm it's dead (`unverified`),
or fail to complete at all — network error, provider 5xx, rate limit
(`indeterminate`). Every output format carries a `verdict` field alongside
the legacy `verified` boolean (kept for backward compatibility, but it
cannot distinguish "provider said no" from "we couldn't ask"):

| Surface | Field |
|---|---|
| `--format json` | `verdict` (`"verified"` \| `"unverified"` \| `"indeterminate"`), plus legacy `verified` bool and `verification_error` |
| `--format sarif` | `properties.verdict`, plus legacy `properties.verified` |
| `--format table` | `VERDICT` column: `✓` verified, `✗` unverified, `?` indeterminate |

## Severity defaults

| Finding | Severity |
|---|---|
| Verified secret | Critical |
| Indeterminate secret (verification attempt failed) | Critical |
| Unverified named secret detector | High |
| Generic high entropy / JWT / PEM unverified | Medium |
| PII | Medium |

Indeterminate is deliberately as severe as Verified, not Unverified: a
failed verification attempt doesn't disprove liveness, and under-classifying
a possibly-live credential is the wrong failure mode for a secrets scanner.

## Exit-code gating

`--fail-on` controls the exit code:

```sh
pleno-dlp scan filesystem ./repo --fail-on critical
pleno-dlp scan filesystem ./repo --fail-on high
pleno-dlp scan filesystem ./repo --fail-on any
```

To preserve TruffleHog-style verified-only pipelines, use
`--only-verified`. Verification runs by default, and the flag filters
output, finding counts, exit-code gating, and `--revoke-on-verified`
dispatch to provider-confirmed findings.

`--only-verified` keeps `indeterminate` findings by default — a failed
verification attempt (network error, provider 5xx, rate limit) is not the
same as the provider confirming the secret is dead, so dropping it would
silently hide a possibly-live credential caught in a transient outage. A
stderr line reports how many indeterminate findings were kept:

```
only-verified: kept 3 indeterminate finding(s) — verification attempt failed ...
```

Pass `--drop-indeterminate` to restore the strict pre-#246 behaviour and
exclude indeterminate findings too (the same stderr line then reports how
many were dropped instead). `--revoke-on-verified` and `--revoke-spool`
never act on an indeterminate finding regardless of this flag — only a
confirmed-live verdict triggers revocation.

```sh
pleno-dlp scan github --org acme --include-comments --only-verified --format json
```

GitHub scans accept either a PAT / installation token through `--token`
or GitHub App credentials. App credentials are exchanged for short-lived
installation tokens and refreshed before expiry during long scans.

```sh
pleno-dlp scan github --org acme \
  --app-id "$GITHUB_APP_ID" \
  --app-installation-id "$GITHUB_APP_INSTALLATION_ID" \
  --app-private-key-file ./github-app.pem
```

The same fields can be provided through `GITHUB_APP_ID`,
`GITHUB_APP_INSTALLATION_ID`, and `GITHUB_APP_PRIVATE_KEY_FILE`. Use
`GITHUB_APP_PRIVATE_KEY` only when the environment can safely carry
multi-line PEM secrets.

## Incremental source scans

`scan github --incremental --incremental-state <file>` stores both the
overall resource fingerprint and a GitHub source watermark. When the
overall fingerprint is unchanged, the scan is skipped entirely. When
only part of a GitHub org changes, the GitHub connector narrows the
scan to changed resources:

- default-branch blobs whose path, SHA, or size changed since the
  previous successful baseline
- new or updated issue comments
- new or updated pull request review comments

The connector still lists repositories, default-branch trees, and
comment metadata to compute the next watermark, but unchanged blob
contents and unchanged comment bodies are not fetched or scanned.

`scan s3 --incremental --incremental-state <file>` also stores an S3
source watermark. The S3 source still lists object metadata to compute
the next watermark, but unchanged object bodies are not fetched or
scanned. Objects are considered unchanged when their key, ETag, size,
and last-modified timestamp match the previous successful baseline.

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
