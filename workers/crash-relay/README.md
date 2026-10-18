# Crash relay contract (vendored)

This directory vendors the `validate()` path of the
[`plenoai/plenoai.com`](https://github.com/plenoai/plenoai.com) crash relay
(`workers/crash-relay/crash-relay.js`) so the client <-> relay contract is
tested in this repo's CI as well as in the relay's own repo.

The single source of truth is
[`pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json`](../../pkg/telemetry/crash/schema/pleno-dlp.crash.v1.json).
Three tests keep it honest:

| Side | Test | Fails when |
|---|---|---|
| Go client | `pkg/telemetry/crash/report_test.go` | the `Report` struct and the schema allowlist/required set drift |
| Relay (here) | `crash-relay.test.js` | the relay's `ALLOWED_FIELDS` / `REQUIRED_FIELDS` and the schema drift |
| Relay (upstream) | the relay's own test | the relay and its vendored schema copy drift |

Run the vendored relay test:

```sh
node --test workers/crash-relay/crash-relay.test.js
```

## Syncing with upstream

The upstream relay is the owner of its `validate()` implementation. When
it changes, re-vendor `crash-relay.js` here in the same PR that updates
`schema/pleno-dlp.crash.v1.json`, then run the test above. Do not add a
field to one side without the other — that is exactly the drift this
contract exists to catch.
