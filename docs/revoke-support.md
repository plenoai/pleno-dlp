# Revoke support

Use `pleno-dlp detectors list --revoke-support` for the runtime answer.
This page keeps the static contract: gating, idempotency, provider requirements, and caveats.

**Scope note:** as far as we have measured (`docs/comparison.md`
benchmarks pleno-dlp against trufflehog and gitleaks, the two other OSS
secret scanners in that comparison), pleno-dlp is currently the only
OSS tool of the three with **headless revoke** — a non-interactive,
CLI-only path from a detected leak to an invalidated credential,
scriptable in CI without a human clicking through a provider's web
console. That is a narrower, falsifiable claim, not "zero competition":
it says nothing about commercial/SaaS DLP products, provider-native
auto-revoke integrations (e.g. a provider's own secret-scanning partner
program), or tools outside that three-way comparison. Framing it any
more broadly than "only OSS headless revoke, among the tools we've
benchmarked" would be an overclaim this repo does not stand behind.

## Audit trail

Every revoke attempt — through `--detector`/`--secret`,
`--revoke-from-spool`, or `scan --revoke-on-verified` — emits one
schema-versioned JSON Lines record via `--audit-trail <path>` (falls
back to stderr if omitted, never silently dropped). Schema and field
reference: [`docs/audit-trail-schema.md`](audit-trail-schema.md).

## Severity recap

Revoke runs only against **verified** findings. Scan-mode verification runs by
default, so `scan --revoke-on-verified` can dispatch only provider-confirmed
findings.

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
   only dispatches verified findings; revoking unverified candidates
   would risk invalidating tokens that are not ours.
   `--revoke-dry-run` previews the work without contacting any
   provider and bypasses only the env-var gate (operators previewing
   work shouldn't have to mark CI as ready-to-revoke).

`Revoker.Revoke` implementations do not enforce local policy. The caller owns gating.

## Deferred revoke via spool

For workflows that want scan and revoke decoupled — separate trust
boundaries, replayable revokes, or a human review gate between
detection and revocation — use the spool path:

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
Pick one trust model: inline revoke happens during scan, deferred
spool lets a second invocation own the irreversible step.

Spool record shape (v1):

```json
{"version":1,"detector":"GitHub","secret_b64":"...","redacted":"ghp_***","source_link":"https://github.com/...","ts":"2026-06-19T..."}
```

`pleno-dlp revoke --revoke-from-spool` iterates the file and dispatches
each line to the matching `Revoker`. Lines whose detector lacks a
Revoker are counted as skipped, not failed. The same gating rules
apply once for the batch: `--confirm`/`--dry-run` and
`PLENO_DLP_ALLOW_REVOKE=1` in non-interactive contexts.

After a successful revoke pass, delete the spool file —
`PLENO_DLP_ALLOW_RAW_EXPORT` does not protect against an operator
leaving raw secrets at rest indefinitely.

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
  the context, `scan --revoke-on-verified` skips the finding and
  reports it in the end-of-scan summary as `skipped-no-revoker=…`
  alongside genuinely unsupported detectors.
- **unsupported** — `Revoker` is not implemented. The provider may or
  may not expose a public revocation API; absence here means we do
  not currently route through one.

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
`revoked_at`, `provider_id`, `dry_run`, and `error` fields. For a
durable, schema-versioned trail across many invocations (rather than
one process's stdout), pass `--audit-trail <path>` — see
[`docs/audit-trail-schema.md`](audit-trail-schema.md).

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
