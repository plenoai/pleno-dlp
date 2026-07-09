# Audit trail schema (v1)

Every revoke attempt — through any of the three code paths described
below — emits exactly one record to the audit trail. The schema is
defined in Go at [`pkg/audit`](../pkg/audit/audit.go)
(`audit.Record`, `audit.SchemaVersion`); this page is the published,
human-readable mirror of that file. The two move together: any field
added, renamed, or removed in `pkg/audit/audit.go` requires an update
here in the same change, and a breaking change to a field's meaning or
shape (not a purely additive `omitempty` field) requires bumping
`schema_version`.

## Encoding: JSON Lines

The trail is JSON Lines — one self-contained JSON object per line,
append-only. This mirrors the existing revoke-spool format
(`docs/revoke-support.md`), which is already JSONL for the same
reasons: streamable, greppable, `jq`-able, and safe to `tail -f` during
a long-running batch revoke.

```json
{"schema_version":"1","trail_id":"3f1c9a2b7d4e6f01","ts":"2026-07-10T12:00:00Z","path":"on-verified","detector":"GitHub","secret_hash":"1b2e...64hex","redacted":"ghp_0123...","revoked":true,"revoked_at":"2026-07-10T12:00:02Z","provider_id":"","dry_run":false,"target_link":"https://github.com/acme/repo/blob/main/leak.env"}
```

## Where the trail goes

Every code path accepts `--audit-trail <path>`:

- `pleno-dlp revoke --detector ... --secret ... --audit-trail trail.jsonl`
- `pleno-dlp revoke --revoke-from-spool spool.jsonl --audit-trail trail.jsonl`
- `pleno-dlp scan --revoke-on-verified --audit-trail trail.jsonl ...`

The flag is optional but the trail is not: when `--audit-trail` is
omitted, records are written to the command's stderr instead of being
dropped. This mirrors the codebase's existing "safe default is to
surface everything" rule (`--only-verified` defaults off for the same
reason) — an audit trail that silently disappears when you forget a
flag is not an audit trail. Pass `--audit-trail` when you want a
durable, greppable file instead of an ephemeral stderr stream; the file
is opened append-only, mode `0600`, and accumulates across
invocations (unlike the revoke spool file, which is truncate-and-replace
by design — the audit trail is meant to persist).

## Field table

| Field           | Type   | Always present | Meaning |
|-----------------|--------|-----------------|---------|
| `schema_version`| string | yes | Pins this record to this table. `"1"` today. Check before assuming field semantics — the same contract `spoolRecord.version` already establishes for the revoke spool file. |
| `trail_id`      | string | yes | Correlates this record with other artifacts from the same attempt — in particular the `audit_trail_id` key stamped into the originating finding's `extra_data` (json output) / `properties` (SARIF output) by the on-verified path. Derived deterministically from `(detector, secret_hash, ts)`, not random. |
| `ts`            | string (RFC3339, UTC) | yes | When the attempt was initiated — the same instant `trail_id` was derived from. Not the completion time; see `revoked_at`. |
| `path`          | string | yes | Which revoke code path produced this record: `single`, `spool`, or `on-verified` (see below). |
| `detector`      | string | yes | `DetectorType.String()` — the same identifier used throughout `pkg/output` and `pkg/detectors` (e.g. `GitHub`, `SlackBotToken`, `Stripe`). |
| `secret_hash`   | string (sha256 hex) | yes | `sha256(raw secret)`, hex-encoded. The only secret-derived field. Comparable to `pkg/output`'s `secret_hash` JSON field for the same leaked value — a scan's JSON output and the audit trail can be joined on this without either side ever holding the raw secret. |
| `redacted`      | string | no | Prefix + ellipsis rendering, identical to `detectors.Result.Redacted` / `revoke --format json`'s `redacted_secret`. Safe to display. |
| `revoked`       | bool   | yes | The provider's confirmation that the credential is now dead. `false` for a `--dry-run` preview or a failed/declined attempt. |
| `revoked_at`    | string (RFC3339, UTC) | no | When the provider confirmed revocation. Empty when `revoked` is false or the provider does not report a completion time. |
| `provider_id`   | string | no | Provider-specific non-secret identifier for the revoked credential (e.g. Stripe's key-prefix diagnostic). |
| `dry_run`       | bool   | no | `true` marks a preview record: no provider call was made. |
| `target_link`   | string | no | Best-effort non-secret locator for where the credential was found — a GitHub file URL, a SIEM link, a spool record's `source_link`. Empty when the path has no such context (e.g. `revoke --secret` supplied directly with no source chunk). |
| `error`         | string | no | Provider diagnostic on a failed attempt, or the idempotent-success diagnostic ("already revoked") when `revoked` is still true — same dual use as `revokeRecord.Error` in `revoke --format json`. |

### `path` values

| Value         | CLI entry point                              | One record per |
|---------------|-----------------------------------------------|-----------------|
| `single`      | `pleno-dlp revoke --detector <d> --secret <s>` | invocation |
| `spool`       | `pleno-dlp revoke --revoke-from-spool <file>`  | dispatched spool line |
| `on-verified` | `pleno-dlp scan --revoke-on-verified`          | verified finding whose detector implements `Revoker` |

`scan --revoke-spool` (writing the spool file) is **not** a revoke
attempt — no provider is contacted, so it does not emit a trail record.
The record is emitted later, when that spool is replayed through
`revoke --revoke-from-spool` and an actual (or dry-run) revoke is
dispatched.

## What is never in a record

No field carries the raw secret. `secret_hash` and `redacted` are the
only secret-derived fields, and both are structurally incapable of
reconstructing the original value — this is enforced by
`pkg/audit.New` being the only constructor for `Record` and by hashing
the secret immediately rather than accepting a pre-computed hash from
a caller. `pkg/audit/audit_test.go` asserts no record's JSON encoding
ever contains the input secret string, for both populated and edge-case
(empty, very short) inputs.

## SARIF integration

`scan --revoke-on-verified` findings that are eligible for revoke (a
`VerdictVerified` result whose detector implements `Revoker`) carry an
additional `audit_trail_id` key in `extra_data` (json output) /
`properties` (SARIF output) — the same value as that attempt's
`trail_id`. This is how a SARIF result correlates back to its audit
trail record.

The full outcome fields (`revoked`, `revoked_at`, `provider_id`,
`error`) cannot be embedded in the *same* SARIF document as the
finding: SARIF is a single buffered JSON document finalized inside the
same `Emit` call that forwards the finding downstream, and that happens
*before* the revoke's network round trip completes (see the ordering
rationale in `cmd/pleno-dlp/cmd/revoke_on_verified.go`). Forwarding the
finding only after the revoke result was known was considered and
rejected — it would mean a panicking or hanging provider call could
silently drop findings the operator paid to scan, which is a strictly
worse failure mode than an extra correlation hop. Join
`properties.audit_trail_id` against the JSONL trail (`--audit-trail
<path>`) to get the outcome.

`audit.Record.ToSARIFProperties()` defines the matching properties-bag
shape for callers who post-process a SARIF file and want to merge a
full record in — e.g. `properties["audit_trail"] =
rec.ToSARIFProperties()`. It round-trips through the same JSON
encoding as the JSON Lines file, so the two representations cannot
silently drift apart; `pkg/audit/audit_test.go` pins this equivalence.

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
  real-shaped secret, an empty secret, and a short secret).
- `schema_version` is present and equals the documented literal.
- `trail_id` is deterministic for identical `(detector, secret, ts)`
  input and differs when any of the three changes.
- `ToSARIFProperties()` produces the same key/value shape as the JSON
  Lines encoding of the same record.
- `audit.Writer` serializes concurrent `Write` calls so lines never
  interleave, since `scan --revoke-on-verified` dispatches from engine
  worker goroutines.

`cmd/pleno-dlp/cmd/audit_trail_test.go` and
`cmd/pleno-dlp/cmd/scan_test.go` additionally cover, end to end through
the real CLI commands (via `--dry-run`/`--revoke-dry-run`, so no
provider is contacted):

- `revoke --detector --secret` (`single`) writes a well-formed record
  to `--audit-trail` and never writes the raw secret to the trail file
  or to stderr.
- Omitting `--audit-trail` still surfaces a well-formed record on
  stderr — the trail is never silently dropped.
- `revoke --revoke-from-spool` (`spool`) writes one record per line,
  carrying the spool's `source_link` forward as `target_link`.
- `scan --revoke-on-verified` (`on-verified`) stamps the forwarded
  finding's `extra_data`/SARIF `properties` with `audit_trail_id`, and
  that value matches the corresponding trail record's `trail_id`.
- An `Indeterminate` or `Unverified` finding is never stamped and never
  produces a trail record (revocation must never fire on anything but a
  confirmed-live verdict — issue #246's guarantee extends unchanged to
  the audit trail).
