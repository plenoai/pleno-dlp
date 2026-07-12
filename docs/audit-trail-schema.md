# Audit trail schema (v1)

Every revoke attempt emits exactly one record to the audit trail,
whichever of the three code paths described below it takes. The schema is
defined in Go at [`pkg/audit`](../pkg/audit/audit.go)
(`audit.Record`, `audit.SchemaVersion`); this page is the published,
human-readable mirror of that file.

## Encoding: JSON Lines

The trail is JSON Lines: one self-contained JSON object per line,
append-only.

```json
{"schema_version":"1","trail_id":"3f1c9a2b7d4e6f01","ts":"2026-07-10T12:00:00Z","path":"on-verified","detector":"GitHub","secret_hash":"1b2e...64hex","redacted":"ghp_0123...","revoked":true,"revoked_at":"2026-07-10T12:00:02Z","target_link":"https://github.com/acme/repo/blob/main/leak.env"}
```

## Where the trail goes

Every code path accepts `--audit-trail <path>`:

- `pleno-dlp revoke --detector ... --secret ... --confirm --audit-trail trail.jsonl`
- `pleno-dlp revoke --revoke-from-spool spool.jsonl --confirm --audit-trail trail.jsonl`
- `PLENO_DLP_ALLOW_REVOKE=1 pleno-dlp scan --revoke-on-verified --audit-trail trail.jsonl ...`

When `--audit-trail` is omitted, records are written to the command's
stderr. Pass `--audit-trail` when you want a
file instead of a stderr stream; the file is opened append-only, mode
`0600`, and accumulates across invocations.

## Field table

| Field           | Type   | Always present | Meaning |
|-----------------|--------|-----------------|---------|
| `schema_version`| string | yes | Pins this record to this table. `"1"` today. |
| `trail_id`      | string | yes | Correlates this record with other artifacts from the same attempt. Derived deterministically from the detector, `secret_hash`, and the nanosecond-precision initiation instant; the record's `ts` truncates that instant to seconds, so `trail_id` is not recomputable from the record's fields alone. |
| `ts`            | string (RFC3339, UTC) | yes | When the attempt was initiated (the same instant `trail_id` was derived from). Completion time lives in `revoked_at`. |
| `path`          | string | yes | Which revoke code path produced this record: `single`, `spool`, or `on-verified` (see below). |
| `detector`      | string | yes | `DetectorType.String()`, the same identifier used throughout `pkg/output` and `pkg/detectors` (e.g. `GitHub`, `SlackBotToken`, `Stripe`). |
| `secret_hash`   | string (sha256 hex) | yes | `sha256(raw secret)`, hex-encoded. Comparable to `pkg/output`'s `secret_hash` JSON field for the same leaked value, so a scan's JSON output and the audit trail can be joined on this without either side ever holding the raw secret. |
| `redacted`      | string | no | Prefix + ellipsis rendering, identical to `detectors.Result.Redacted` / `revoke --format json`'s `redacted_secret`, and safe to display. |
| `revoked`       | bool   | yes | The provider's confirmation that the credential is now dead. `false` for a `--dry-run` preview or a failed/declined attempt. |
| `revoked_at`    | string (RFC3339, UTC) | no | When the provider confirmed revocation. Empty when `revoked` is false or the provider does not report a completion time. |
| `provider_id`   | string | no | Provider-specific non-secret identifier for the revoked credential (e.g. Stripe's key-prefix diagnostic). |
| `dry_run`       | bool   | no | `true` marks a preview record: no provider call was made. |
| `target_link`   | string | no | Best-effort non-secret locator for where the credential was found: a GitHub file URL, a SIEM link, a spool record's `source_link`. Empty when the path has no such context (e.g. `revoke --secret` supplied directly with no source chunk). |
| `error`         | string | no | Provider diagnostic on a failed attempt, or the idempotent-success diagnostic ("already revoked") when `revoked` is still true. |

### `path` values

| Value         | CLI entry point                              | One record per |
|---------------|-----------------------------------------------|-----------------|
| `single`      | `pleno-dlp revoke --detector <d> --secret <s>` | invocation |
| `spool`       | `pleno-dlp revoke --revoke-from-spool <file>`  | dispatched spool line |
| `on-verified` | `pleno-dlp scan --revoke-on-verified`          | verified finding whose detector implements `Revoker` |

`scan --revoke-spool` (writing the spool file) is **not** a revoke
attempt: no provider is contacted, so it emits no trail record.
The record appears later, when that spool is replayed through
`revoke --revoke-from-spool` and an actual (or dry-run) revoke is
dispatched.

## What is never in a record

No field carries the raw secret. `secret_hash` and `redacted` are the
only secret-derived fields.

## SARIF integration

`scan --revoke-on-verified` findings that are eligible for revoke (a
`VerdictVerified` result whose detector implements `Revoker`) carry an
additional `audit_trail_id` key in `extra_data` (json output) /
`properties` (SARIF output), carrying the same value as that attempt's
`trail_id`. This is how a SARIF result correlates back to its audit
trail record.

The full outcome fields (`revoked`, `revoked_at`, `provider_id`,
`error`) cannot be embedded in the same SARIF document as the
finding. The finding's SARIF result, properties bag included,
is snapshotted inside the `Emit` call that dispatches the revoke,
before the revoke's network round trip completes; the buffered
document is only serialized at `Close`, but by then each result is
already frozen (see the ordering rationale in
`cmd/pleno-dlp/cmd/revoke_on_verified.go`). Join
`properties.audit_trail_id` against the JSONL trail (`--audit-trail
<path>`) to get the outcome.

`audit.Record.ToSARIFProperties()` defines the matching properties-bag
shape for callers who post-process a SARIF file and want to merge a
full record in, e.g. `properties["audit_trail"] =
rec.ToSARIFProperties()`. It round-trips through the same JSON
encoding as the JSON Lines file.

## Versioning policy

- Additive change (new `omitempty` field, new `path` value existing
  readers can ignore): no version bump, update this table.
- Breaking change (rename, type change, changed meaning of an existing
  field, removing a field): bump `audit.SchemaVersion` and add a
  "Schema v2" section here describing the delta, the same way
  `spoolRecordVersion` is handled for the revoke spool file.
- Readers MUST check `schema_version` before assuming field semantics.
  A reader encountering an unrecognized version should log and skip the
  record rather than guess at its shape.

## Redaction test coverage

`pkg/audit/audit_test.go` covers:

- `secret_hash` never equals the raw input and the record's JSON
  encoding never contains the raw secret substring (checked for a
  realistic secret, an empty secret, and a short secret).
- `schema_version` is present and equals the documented literal.
- `trail_id` is deterministic for identical `(detector, secret, ts)`
  input and differs when the detector or timestamp changes.
- `ToSARIFProperties()` produces the same key/value shape as the JSON
  Lines encoding of the same record.
- `audit.Writer` serializes concurrent `Write` calls so lines never
  interleave, since `scan --revoke-on-verified` dispatches from engine
  worker goroutines.

`cmd/pleno-dlp/cmd/audit_trail_test.go` covers the `single`, `spool`,
and stderr-fallback cases end to end through the CLI commands
(via `--dry-run`, so no provider is contacted); the on-verified
guarantees below are covered at the sink level in
`cmd/pleno-dlp/cmd/scan_test.go`
(`TestRevokingSink_VerifiedFindingDispatches`,
`TestRevokingSink_NeverRevokesIndeterminate`), with the real
`scan --revoke-on-verified --audit-trail` invocation checked only for
flag wiring and trail-file creation:

- `revoke --detector --secret` (`single`) writes a well-formed record
  to `--audit-trail` and never writes the raw secret to the trail file
  or to stderr.
- Omitting `--audit-trail` still surfaces a well-formed record on
  stderr; the trail is never silently dropped.
- `revoke --revoke-from-spool` (`spool`) writes one record per line,
  carrying the spool's `source_link` forward as `target_link`.
- `scan --revoke-on-verified` (`on-verified`) stamps the forwarded
  finding's `extra_data`/SARIF `properties` with `audit_trail_id`, and
  that value matches the corresponding trail record's `trail_id`.
- An `Indeterminate` or `Unverified` finding is never stamped and never
  produces a trail record (revocation must never fire on anything but a
  confirmed-live verdict — issue #246's guarantee extends unchanged to
  the audit trail).
