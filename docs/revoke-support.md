# Revoke support

Use `pleno-dlp detectors list --revoke-support` for the runtime answer.
This page keeps the static contract.

**Scope note:** as far as we have measured (`docs/comparison.md`
benchmarks pleno-dlp against trufflehog and gitleaks, the two other OSS
secret scanners in that comparison), pleno-dlp is currently the only
OSS tool of the three with **headless revoke**: a non-interactive,
CLI-only path from a detected leak to an invalidated credential.
The claim is narrow and falsifiable. It says nothing about
commercial/SaaS DLP products, provider-native auto-revoke integrations
(e.g. a provider's own secret-scanning partner program), or tools
outside that three-way comparison.

## Audit trail

Every revoke attempt — through `--detector`/`--secret`,
`--revoke-from-spool`, or `scan --revoke-on-verified` — emits one
schema-versioned JSON Lines record via `--audit-trail <path>` (falls
back to stderr if omitted).
[`docs/audit-trail-schema.md`](audit-trail-schema.md) documents the
schema and each field.

## Severity recap

Scan-driven revoke (`--revoke-on-verified`, `--revoke-spool`) dispatches
only detector-verified findings; scan-mode verification runs by default.
For side effects that require an audited provider-confirmed result, combine
revocation with `--only-provider-confirmed`.
`pleno-dlp revoke --detector/--secret` acts on whatever secret the
operator supplies, without a verification step.

## Safety gating

Revoke is irreversible. The CLI applies three gates:

1. **Mode flag.** `pleno-dlp revoke` requires one of `--confirm` or
   `--dry-run`. Without either, the command refuses with exit code 2.
   Because provider/transport failures also exit 2, the exit code
   alone cannot identify a gate refusal; check stderr for
   `revoke: refusing to proceed without --confirm or --dry-run`.
2. **Environment opt-in for non-interactive contexts.** When the
   command runs against a non-TTY stdin (CI, pipes, scripts),
   `PLENO_DLP_ALLOW_REVOKE=1` must be set in addition to `--confirm`.
   TTY-attached operators do not need the env var.
3. **Scan-mode opt-in.** `scan --revoke-on-verified` always requires
   `PLENO_DLP_ALLOW_REVOKE=1` regardless of TTY state. The flag
   only dispatches verified findings; revoking unverified candidates
   risks invalidating credentials that belong to an unrelated party.
   `--revoke-dry-run` previews the work without contacting any
   provider and bypasses only the env-var gate.

`Revoker.Revoke` implementations do not enforce local policy.

## Deferred revoke via spool

For workflows that want scan and revoke decoupled, use the spool path:

```sh
PLENO_DLP_ALLOW_RAW_EXPORT=1 \
  pleno-dlp scan github --org acme --revoke-spool revoke.jsonl

# Inspect revoke.jsonl, decide to proceed, then:
PLENO_DLP_ALLOW_REVOKE=1 \
  pleno-dlp revoke --confirm --revoke-from-spool revoke.jsonl
```

The spool file is JSONL, one record per verified finding whose
detector implements `Revoker`. The file is created with mode `0600`
and **contains raw secret bytes** — `PLENO_DLP_ALLOW_RAW_EXPORT=1` is
required to opt in to serializing live credentials to disk.

`--revoke-spool` is mutually exclusive with `--revoke-on-verified`.

Spool record shape (v1):

```json
{"version":1,"detector":"GitHub","secret_b64":"...","redacted":"ghp_***","source_link":"https://github.com/...","ts":"2026-06-19T..."}
```

`pleno-dlp revoke --revoke-from-spool` iterates the file and dispatches
each line to the matching `Revoker`. Known limitation: spool lines
record the detector type name (e.g. `SlackBotToken`), and
`SlackBotToken` currently fails to resolve to the slack `Revoker`, so
Slack lines are counted as skipped rather than revoked. Lines whose
detector lacks a Revoker also land in the skipped count; they never
count as failures. The same gating rules
apply once for the batch: `--confirm`/`--dry-run` and
`PLENO_DLP_ALLOW_REVOKE=1` in non-interactive contexts.

After a successful revoke pass, delete the spool file.
`PLENO_DLP_ALLOW_RAW_EXPORT` only gates the write; it does nothing
about raw secrets an operator leaves at rest indefinitely.

## Idempotency contract

`Revoke(ctx, secret)` MUST be idempotent. A second call against an
already-revoked secret returns `Revoked=true` with a non-nil
`RevokeResult.Err` describing why the provider response was unusual
(e.g. "token already revoked", "already deleted"). Hard failures
(transport, 5xx, rate-limit) surface via the second return value;
`RevokeResult.Err` is reserved for provider-acknowledged diagnostics.

## Detector × provider matrix

| Detector            | Revoke API                                                         | Path through                                                  | Status             |
|---------------------|--------------------------------------------------------------------|---------------------------------------------------------------|--------------------|
| `GitHub`            | `POST /credentials/revoke` for PATs; `DELETE /applications/{client_id}/token` for OAuth-app tokens | `pkg/detectors/github` (Scanner.Revoke)                       | supported          |
| `GitLab`            | 2-step: `GET /personal_access_tokens/self` → `POST .../{id}/revoke` | `pkg/detectors/gitlab` (Scanner.Revoke)                       | supported          |
| `SlackBotToken`     | `POST /api/auth.revoke`                                            | `pkg/detectors/slack` (Scanner.Revoke)                        | supported          |
| `Stripe`            | `POST /v1/api_keys/{key}/revoke`                                   | `pkg/detectors/stripe` (Scanner.Revoke)                       | supported (rk_ only) |
| `AWS`               | IAM `DeleteAccessKey` action (SigV4 signed)                        | `pkg/detectors/aws` (Scanner.Revoke)                          | context-required   |

Status semantics:

- **supported** — `Revoker` is implemented and runs without operator
  setup beyond the standard CLI gating.
- **context-required** — `Revoker` is implemented but cannot run
  without operator-supplied principal context (see AWS below). Without
  the context, `scan --revoke-on-verified` still dispatches the
  finding; the attempt fails with a missing-credentials error and is
  reported in the end-of-scan summary under `failed=…` (with a
  `revoke FAIL:` stderr line), not under `skipped-no-revoker=…`.
- **unsupported** — `Revoker` is not implemented.

## Provider-specific notes

### GitHub PAT / OAuth-app tokens

GitHub revoke defaults to `auto` mode. When OAuth-app credentials are
not configured, `pleno-dlp` calls GitHub's unauthenticated
`POST /credentials/revoke` endpoint with the leaked credential in a
single-element `credentials` array. This is the right path for normal
classic and fine-grained PAT leaks; the request intentionally does not
send an `Authorization` header.

When OAuth-app credentials are configured, `auto` mode preserves the
older OAuth-app path: `DELETE /applications/{client_id}/token`. That
endpoint only revokes tokens issued by the configured OAuth
application. Raw user-owned PATs (`ghp_…` not minted by that app)
reject with HTTP 422 and surface as `Revoked=false` with a non-fatal
diagnostic in `RevokeResult.Err`. Idempotent: HTTP 404 →
`Revoked=true` with a "already revoked or never existed" diagnostic.

Mode selection:

- `--github-revoke-mode credentials` or
  `PLENO_DLP_REVOKE_GITHUB_MODE=credentials` forces PAT
  `POST /credentials/revoke`.
- `--github-revoke-mode oauth-app` or
  `PLENO_DLP_REVOKE_GITHUB_MODE=oauth-app` forces OAuth-app revoke.
- `auto` chooses OAuth-app mode when client credentials are present,
  otherwise credentials mode.

OAuth-app credentials wire through:

- `--client-id` / `--client-secret` (CLI override), or
- `PLENO_DLP_REVOKE_GITHUB_CLIENT_ID` /
  `PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET` (env fallback).

### GitLab PAT

GitLab's PATs self-revoke via Bearer auth. The detector uses the
standard 2-step flow:

1. `GET /api/v4/personal_access_tokens/self` (Bearer) → returns the
   numeric PAT id.
2. `POST /api/v4/personal_access_tokens/{id}/revoke` (same Bearer).

No additional CLI plumbing is required beyond passing the leaked
token to `--secret`. The GitLab API base is hard-coded to
https://gitlab.com (an unexported package variable, overridden only in
tests); self-hosted GitLab is not currently supported for revoke —
file an issue if you need it.

### Slack

Slack revoke is implemented for the `SlackBotToken` detector
(`xoxb-`). `revoke --detector slack --secret …` will send any
operator-supplied token to `auth.revoke`; shapes the endpoint does not
accept surface as FAIL with the provider's error string. On success
and provider-level rejection the endpoint returns HTTP 200 with the
classification in the JSON body; HTTP 429 and 5xx responses surface as
hard errors. We treat
`token_revoked`/`invalid_auth`/`not_authed` as idempotent successes
because each indicates the credential is no longer usable.

### Stripe (restricted keys only)

Stripe's revoke API only accepts **restricted keys** (`rk_test_` /
`rk_live_`). Secret keys (`sk_test_` / `sk_live_`) cannot be revoked
programmatically — they must be rotated via the Stripe Dashboard. The
detector hard-rejects non-`rk_` inputs with an explanatory error, so
an `sk_` key never gets reported as successfully rotated.

The `ProviderID` field carries the key's prefix plus the first four
characters of the body so audit logs correlate revocations without
storing the live secret.

### AWS access key (context-required)

AWS's `iam:DeleteAccessKey` is keyed on `(UserName, AccessKeyId)`.
The leaked Access Key ID alone is not sufficient — IAM does not
expose a "look up the user that owns this key" endpoint to
unauthenticated callers, and even authenticated callers need
`iam:ListAccessKeys` enumeration which costs more privilege than
many revoke-only roles should hold.

The CLI requires the operator to supply the target IAM user name plus
admin credentials authorized to call DeleteAccessKey:

| Field                         | CLI flag                                  | Env var                                         |
|-------------------------------|-------------------------------------------|-------------------------------------------------|
| Admin access key id           | `--aws-admin-access-key-id`               | `PLENO_DLP_REVOKE_AWS_ADMIN_ACCESS_KEY_ID`      |
| Admin secret access key       | `--aws-admin-secret-access-key`           | `PLENO_DLP_REVOKE_AWS_ADMIN_SECRET_ACCESS_KEY`  |
| Admin session token (opt.)    | `--aws-admin-session-token`               | `PLENO_DLP_REVOKE_AWS_ADMIN_SESSION_TOKEN`      |
| Target IAM user name          | `--aws-user-name`                         | `PLENO_DLP_REVOKE_AWS_USER_NAME`                |
| Region (default `us-east-1`)  | `--aws-region`                            | `PLENO_DLP_REVOKE_AWS_REGION`                   |

NoSuchEntity responses are treated as idempotent successes.

Operators batching AWS revocations should script
`pleno-dlp revoke --detector aws` with the
correct `--aws-user-name` per finding rather than relying on the scan
flag.

## Failure handling

There is no rollback: once a token is invalidated the operator must
mint a fresh one through the provider's normal flow. The CLI logs
revoke outcomes so a post-mortem can reconstruct what happened:
`scan --revoke-on-verified` and table-mode `pleno-dlp revoke` write
outcome lines to stderr; `revoke --format json` writes the structured
record to stdout instead. Structured callers should prefer
`pleno-dlp revoke --format json`, which emits one record per
invocation on stdout with `detector`, `redacted_secret`, `revoked`,
`revoked_at`, `provider_id`, `dry_run`, and `error` fields.

Rate-limit responses (HTTP 429) surface as hard errors; the CLI does
not retry. For batch revocations, set `--rate-limit-rps` on the
`revoke` command to install a per-host limiter via `pkg/verify` so
many sequential revokes against the same provider do not trip
provider quotas.

## CI usage pattern

The recommended automation pattern:

```yaml
- name: Scan + revoke verified leaks
  env:
    PLENO_DLP_ALLOW_REVOKE: "1"
    PLENO_DLP_REVOKE_GITHUB_CLIENT_ID: ${{ secrets.OAUTH_APP_CLIENT_ID }}
    PLENO_DLP_REVOKE_GITHUB_CLIENT_SECRET: ${{ secrets.OAUTH_APP_CLIENT_SECRET }}
  run: |
    pleno-dlp scan --revoke-on-verified \
      --revoke-dry-run \
      --format json filesystem .
```

Production runbooks should pin the detector set with
`--include-detectors`.

## Querying support at runtime

```
pleno-dlp detectors list --revoke-support --format=json
```

emits a JSON array with one object per detector; each object carries
`revokes` (bool, omitted when false) and `revoke_status`
("supported" | "context-required" | "unsupported") alongside
`verifies`. Add `--verify-status` to also populate `verify_status`.
The same data renders as a table when `--format` is omitted.
