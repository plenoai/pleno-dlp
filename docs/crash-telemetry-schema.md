# Crash report schema (pleno-dlp.crash/v1)

When pleno-dlp panics, the client in
[`pkg/telemetry/crash`](../pkg/telemetry/crash/report.go) may emit at most
one crash report to the `plenoai.com` crash relay. The relay accepts a
report only if it carries exactly the fields in this schema and every
required field is present; any extra key is rejected so a future client
field cannot leak scanned content without the relay changing in lockstep.

The schema is published once, as JSON:
[`pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json`](../pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json).
It is the single source of truth, and its `properties` map **is** the
allowlist.

## Contract enforcement

| Side | Test | Fails when |
|---|---|---|
| Go client (this repo) | `pkg/telemetry/crash/report_test.go` | the `Report` struct tags drift from the schema |
| Relay (vendored here) | `workers/crash-relay/crash-relay.test.js` | the relay `validate()` allowlist drifts from the schema |
| Relay (plenoai.com) | the relay's own test | its `validate()` drifts from its vendored schema copy |

Run locally:

```sh
go test ./pkg/telemetry/crash
node --test workers/crash-relay/crash-relay.test.js
```

The relay lives in `plenoai/plenoai.com` (`workers/crash-relay/crash-relay.js`).
That repo's test loads the same schema file (or vendors it); vendoring is
what this repo does with the relay so drift fails CI on either side.

## Field table

| Field | Type | Required | Meaning |
|-------|------|----------|---------|
| `schema` | string (const `pleno-dlp.crash/v1`) | yes | Pins the payload to this table. The relay rejects any other value. |
| `fingerprint` | string (16 hex) | yes | Groups crashes by cause, independent of version and line numbers. |
| `version` | string | yes | pleno-dlp build version. |
| `commit` | string | yes | pleno-dlp build commit; empty when unknown. |
| `goos` | string | yes | `runtime.GOOS`. |
| `goarch` | string | yes | `runtime.GOARCH`. |
| `go_version` | string | yes | `runtime.Version()`. |
| `command` | string | yes | Redacted top-level subcommand words (e.g. `scan filesystem`); never positional arguments. |
| `flags` | array of string | yes | Names of recognised flags only, never values. |
| `kind` | string (`panic`/`fatal`/`recovered`) | yes | How the crash was captured. |
| `message` | string | yes | Redacted panic/fatal line. Scanned content and secrets must never appear here. |
| `stack` | string | yes | Redacted goroutine dump; capped by the client. |
| `created_at` | string (RFC 3339, UTC) | yes | When the crash was captured, truncated to the minute. |

Every field is required: the Go client never omits one (none are
`omitempty`), so a report always carries the full contract.

## What is never in a report

No field carries scanned file content, a matched secret, or a raw
credential. `command`, `message`, and `stack` are redacted by the client
before they are set. The relay's closed allowlist is the backstop: an
unexpected key is a hard rejection, not a warning.

## Versioning policy

- Additive change (new optional property): update the schema, the
  `Report` struct, and the relay in the same coordinated change. No `$id`
  bump while old readers can ignore the new key.
- Breaking change (rename, type change, changed meaning, removed field,
  or a new required field): bump the `$id` to `pleno-dlp.crash/v2` and
  keep the v1 file until the relay stops accepting v1.
- Readers MUST check `schema` before assuming field semantics.
