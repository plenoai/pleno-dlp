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

## GitHub Action

The two steps above are also available as a single composite action —
[`plenoai/pleno-dlp`](https://github.com/plenoai/pleno-dlp/blob/main/action.yml),
usable via `uses: plenoai/pleno-dlp@vX.Y.Z`:

```yaml
name: pleno-dlp
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # required by upload-sarif

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7

      - uses: plenoai/pleno-dlp@v0.62.0
        id: scan
        with:
          target: .              # default: "."
          sarif-file: results.sarif
          fail-on: high           # default: high (audit-first, see above)

      - uses: github/codeql-action/upload-sarif@v3
        if: always()             # upload even when --fail-on failed the step
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

What the action does before running a scan:

1. Resolves the pleno-dlp version to install — the `version` input if set,
   otherwise the action's own tag ref (`github.action_ref`), so the action
   revision and the binary it runs are always the same signed release.
2. Downloads that release's archive for the runner's OS/arch, plus
   `checksums.txt` and `checksums.txt.sigstore.json`.
3. `cosign verify-blob`s `checksums.txt` against the release workflow's
   Sigstore keyless (OIDC) identity — the same verification described in
   every release's notes — then checks the archive's SHA-256 against the
   now-verified `checksums.txt`.
4. Extracts the verified binary and runs
   `pleno-dlp scan filesystem <target> --format sarif --fail-on <fail-on>`.

Inputs: `target` (default `.`), `version` (default: this action's tag),
`args` (extra space-separated flags), `sarif-file` (default
`pleno-dlp-results.sarif`), `fail-on` (default `high`). Output:
`sarif-file`, the path written.

Marketplace publishing is deferred (a release-time human step); until
then, reference the action by tag as shown above.

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

**Default is `high` (audit-first).** A first scan of an unfamiliar repo
routinely turns up noise — generic high-entropy strings, JWTs, PEM
blocks, PII — that the severity table above already classifies as
Medium. Gating on `any` (the pre-#250 default) meant a single one of
those exited 1 and broke a brand-new CI pipeline before the operator
had a chance to triage anything. `high` still fails the build on every
named-secret detector hit and every verified/critical finding — it
only stops treating Medium-and-below noise as a hard gate. Tighten
with `--fail-on any` once the repo has an allowlist and a clean
baseline; see [`docs/recipes/staged-rollout.md`](recipes/staged-rollout.md)
for the recommended ratchet sequence.

Findings still print and still count even when they don't meet the
gate — nothing is hidden. Whenever a scan has findings that didn't
trip the exit code, the summary says so and names the escape hatch:

```
scanned 12 chunk(s), 4096 byte(s), 3 finding(s) in 42ms
exit gate: --fail-on=high (2 low/medium finding(s) did not affect exit code; use --fail-on=any to block on all)
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

For the opposite trade-off — speed and offline operation over
confidence — `--no-verify` skips every detector's `Verify()` network
round-trip entirely (not merely filtering it out afterward): every
finding's verdict is `unverified` — never `indeterminate`, since that
verdict means an attempt was made and failed, and `--no-verify` means no
attempt is made at all. It is mutually exclusive with `--only-verified`,
which would otherwise always report zero results once nothing is ever
verified. This is what the latency-tolerant `pleno-dlp hooks install`
agent hooks use — see [`docs/hooks.md`](hooks.md) — but it applies to
any scan kind:

```sh
pleno-dlp scan stdin --no-verify --quiet --fail-on any --format json < diff.txt
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

`scan github --incremental --incremental-state <file>` stores the overall
resource fingerprint plus namespaced state for repository history, wikis,
gist history/comments, and collaboration entities. A repository whose
`pushed_at` and history-policy fingerprint are unchanged keeps its prior main
history state without another clone. Otherwise, the connector clones it and walks every
commit reachable from every branch, stopping at the previously recorded ref
heads so already-scanned history is not emitted again.

With `--include-comments`, new or updated issue comments and pull request
review comments are fetched and scanned independently. Comment changes do not
advance `pushed_at`, so the comment pass still runs when repository history is
skipped. REST pages still contain bodies for unchanged comments; the connector
compares cursors and does not re-emit or re-scan them. Wiki and gist checkpoints
advance independently from main repository history.

See [GitHub full-history scanning](recipes/github-history-scan.md) for the
coverage model, API cost, and race-safe resume behavior.

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
