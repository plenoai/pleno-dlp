# Revoke support

Use `pleno-dlp detectors list --revoke-support` for the runtime answer.
This page keeps the static contract: gating, idempotency, provider requirements, and caveats.

## Severity recap

Revoke runs only against **verified** findings. `scan --revoke-on-verified`
therefore requires `--verify`.

## Safety gating

Revoke is irreversible. The CLI applies three gates:

1. **Mode flag.** `pleno-dlp revoke` requires one of `--confirm` or
   `--dry-run`. Without either, the command refuses with exit code 2
   (refused-by-gate, distinct from a transport failure).
2. **Environment opt-in for non-interactive contexts.** When the
   command runs against a non-TTY stdin (CI, pipes, scripts),
   `PLENO_DLP_ALLOW_REVOKE=1` must be set in addition to `--confirm`.
   TTY-attached operators do not need the env var.
3. **Scan-mode opt-in.** `scan --revoke-on-verified` always requires
   `PLENO_DLP_ALLOW_REVOKE=1` regardless of TTY state. The flag
   additionally requires `--verify`; revoking unverified candidates
   would risk invalidating tokens that are not ours.
   `--revoke-dry-run` previews the work without contacting any
   provider and bypasses only the env-var gate (operators previewing
   work shouldn't have to mark CI as ready-to-revoke).

`Revoker.Revoke` implementations do not enforce local policy. The caller owns gating.

## Idempotency contract

`Revoke(ctx, secret)` MUST be idempotent. A second call against an
already-revoked secret returns `Revoked=true` with a non-nil
`RevokeResult.Err` describing why the provider response was unusual
(e.g. "token already revoked", "already deleted"). Hard failures
(transport, 5xx, rate-limit) surface via the second return value;
`RevokeResult.Err` is reserved for provider-acknowledged diagnostics.

This split distinguishes provider rejection, idempotent success, and transport failure.

## Detector × provider matrix

| Detector            | Revoke API                                                         | Path through                                                  | Status             |
|---------------------|--------------------------------------------------------------------|---------------------------------------------------------------|--------------------|
| `GitHub`            | `DELETE /applications/{client_id}/token`                           | `pkg/detectors/github` (Scanner.Revoke)                       | supported          |
| `GitLab`            | 2-step: `GET /personal_access_tokens/self` → `POST .../{id}/revoke` | `pkg/detectors/gitlab` (Scanner.Revoke)                       | supported          |
| `SlackBotToken`     | `POST /api/auth.revoke`                                            | `pkg/detectors/slack` (Scanner.Revoke)                        | supported          |
| `Stripe`            | `POST /v1/api_keys/{key}/revoke`                                   | `pkg/detectors/stripe` (Scanner.Revoke)                       | supported (rk_ only) |
| `AWS`               | IAM `DeleteAccessKey` action (SigV4 signed)                        | `pkg/detectors/aws` (Scanner.Revoke)                          | context-required   |

Status semantics:

- **supported** — `Revoker` is implemented and runs without operator
  setup beyond the standard CLI gating.
- **context-required** — `Revoker` is implemented but cannot run
  without operator-supplied principal context (see AWS below). Without
  the context, `scan --revoke-on-verified` skips the finding and
  reports it in the end-of-scan summary as `skipped-no-revoker=…`
  alongside genuinely unsupported detectors.
- **unsupported** — `Revoker` is not implemented. The provider may or
  may not expose a public revocation API; absence here means we do
  not currently route through one.

## Provider-specific notes

### GitHub PAT

GitHub's `DELETE /applications/{client_id}/token` only revokes tokens
issued by the configured OAuth application. Raw user-owned PATs
(`ghp_…` not minted by an app) reject with HTTP 422 and surface as
`Revoked=false` with a non-fatal diagnostic in `RevokeResult.Err` so
the caller can choose whether to retry against another app or treat
the token as not-ours. Idempotent: HTTP 404 → `Revoked=true` with a
"already revoked or never existed" diagnostic.

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
token to `--secret`. `apiBase` is overridable for self-hosted GitLab
deployments via the detector's package-level variable; the CLI does
not currently expose this — file an issue if you need it.

### Slack

Slack's `auth.revoke` works for every token shape (`xoxb-`, `xoxp-`,
`xoxa-`, `xoxe-`, `xapp-`). The endpoint always returns HTTP 200; the
classification lives in the JSON body. We treat
`token_revoked`/`invalid_auth`/`not_authed` as idempotent successes
because each indicates the credential is no longer usable, even if a
strict reading of the response would only flag the first as "we
revoked it just now".

### Stripe (restricted keys only)

Stripe's revoke API only accepts **restricted keys** (`rk_test_` /
`rk_live_`). Secret keys (`sk_test_` / `sk_live_`) cannot be revoked
programmatically — they must be rotated via the Stripe Dashboard. The
detector hard-rejects non-`rk_` inputs with an explanatory error so
callers cannot believe rotation succeeded for an `sk_` key.

The `ProviderID` field carries the key's prefix plus the first four
characters of the body so audit logs correlate revocations without
storing the live secret. This is intentional: storing the full id
defeats the point of redaction.

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

The signer is inline SigV4 (no AWS SDK dependency). NoSuchEntity
responses are treated as idempotent successes.

When `scan --revoke-on-verified` encounters a verified AWS finding
without the principal context, it cannot revoke and the finding lands
in the `skipped-no-revoker` counter. Operators batching AWS
revocations should script `pleno-dlp revoke --detector aws` with the
correct `--aws-user-name` per finding rather than relying on the scan
flag.

## Failure handling

There is no rollback. Provider-side revocation is a one-way operation;
once a token is invalidated the operator must mint a fresh one through
the provider's normal flow. The CLI logs every revoke outcome to
stderr (`revoke OK:`, `revoke OK (idempotent):`, `revoke FAIL:`) so a
post-mortem can reconstruct what happened. Structured callers should
prefer `pleno-dlp revoke --format json`, which emits one record per
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
    pleno-dlp scan --verify --revoke-on-verified \
      --revoke-dry-run \
      --format json filesystem .
```

Most CI runs should stay on `--revoke-dry-run`. Production runbooks should also
pin the detector set with `--include-detectors`.

## Querying support at runtime

```
pleno-dlp detectors list --revoke-support --format=json
```

emits one JSON object per detector with `revokes` (bool) and
`revoke_status` ("supported" | "context-required" | "unsupported")
fields alongside the existing `verifies` / `verify_status` columns.
The same data renders as a table when `--format` is omitted.

This is the runtime answer for detector revoke support.
